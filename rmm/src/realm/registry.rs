use crate::granule::GRANULE_SIZE;
use crate::measurement::MeasurementError;
use crate::realm::mm::address::GuestPhysAddr;
use crate::realm::mm::page_table::pte::{permission, shareable};
use crate::realm::mm::IPATranslation;
use crate::realm::vcpu::VCPU;
use crate::realm::Realm;
use crate::rmi::realm::Rd;
use crate::rmi::rec::run::{Run, REC_ENTRY_FLAG_EMUL_MMIO};
use crate::rmi::rtt::{RTT_PAGE_LEVEL, S2TTE_STRIDE};

use crate::event::RsiHandle;
use crate::gic;
use crate::gic::{GIC_FEATURES, ICH_HCR_EL2_EOI_COUNT_MASK, ICH_HCR_EL2_NS_MASK};
use crate::granule::{set_granule, GranuleState};
use crate::mm::translation::PageTable;
use crate::realm;
use crate::realm::config::RealmConfig;
use crate::realm::context::Context;
use crate::realm::mm::page_table::pte::attribute;
use crate::realm::mm::stage2_translation::Stage2Translation;
use crate::realm::mm::stage2_tte::{desc_type, invalid_hipas, invalid_ripas};
use crate::realm::mm::stage2_tte::{RttPage, INVALID_UNPROTECTED, S2TTE};
use crate::realm::timer;
use crate::rmi::error::Error;
use crate::rmi::error::InternalError::*;
use crate::rmi::rtt_entry_state;
use crate::rmm_exit;
use crate::rsi::error::Error as RsiError;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use armv9a::{bits_in_reg, regs::*};
use spin::mutex::Mutex;
use spinning_top::Spinlock;

type RealmMutex = Arc<Mutex<Realm<Context>>>;
type RealmMap = BTreeMap<usize, RealmMutex>;
static RMS: Spinlock<(usize, RealmMap)> = Spinlock::new((0, BTreeMap::new()));

fn enter() -> [usize; 4] {
    unsafe {
        if let Some(vcpu) = realm::vcpu::current() {
            if vcpu.is_realm_dead() {
                vcpu.from_current();
            } else {
                vcpu.realm.lock().page_table.lock().clean();
                return rmm_exit([0; 4]);
            }
        }
        [0, 0, 0, 0]
    }
}

fn exit() {
    unsafe {
        if let Some(vcpu) = realm::vcpu::current() {
            vcpu.from_current();
        }
    }
}

pub fn get_realm(id: usize) -> Option<RealmMutex> {
    RMS.lock().1.get(&id).map(|realm| Arc::clone(realm))
}

#[derive(Debug)]
pub struct RMI;
impl RMI {
    pub fn new() -> &'static RMI {
        &RMI {}
    }
}

impl crate::rmi::Interface for RMI {
    fn create_realm(&self, vmid: u16, rtt_base: usize) -> Result<usize, Error> {
        let mut rms = RMS.lock();

        for (_, realm) in &rms.1 {
            if vmid == realm.lock().vmid {
                return Err(Error::RmiErrorInput);
            }
        }

        let id = rms.0;
        let s2_table = Arc::new(Mutex::new(
            Box::new(Stage2Translation::new(rtt_base)) as Box<dyn IPATranslation>
        ));
        let realm = Realm::new(id, vmid, s2_table);

        rms.0 += 1;
        rms.1.insert(id, realm.clone());

        Ok(id)
    }

    fn create_vcpu(&self, id: usize) -> Result<usize, Error> {
        let realm = get_realm(id).ok_or(Error::RmiErrorInput)?;

        let page_table = realm.lock().page_table.lock().get_base_address();
        let vttbr = bits_in_reg(VTTBR_EL2::VMID, id as u64)
            | bits_in_reg(VTTBR_EL2::BADDR, page_table as u64);

        let vcpu = VCPU::new(realm.clone());
        vcpu.lock().context.sys_regs.vttbr = vttbr;
        timer::init_timer(&mut vcpu.lock());
        gic::init_gic(&mut vcpu.lock());

        realm.lock().vcpus.push(vcpu);
        let vcpuid = realm.lock().vcpus.len() - 1;
        Ok(vcpuid)
    }

    fn remove(&self, id: usize) -> Result<(), Error> {
        RMS.lock().1.remove(&id).ok_or(Error::RmiErrorInput)?;
        Ok(())
    }

    fn run(&self, id: usize, vcpu: usize, incr_pc: usize) -> Result<[usize; 4], Error> {
        if incr_pc == 1 {
            get_realm(id)
                .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                .lock()
                .vcpus
                .get(vcpu)
                .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                .lock()
                .context
                .elr += 4;
        }
        debug!(
            "resuming: {:#x}",
            get_realm(id)
                .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                .lock()
                .vcpus
                .get(vcpu)
                .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                .lock()
                .context
                .elr
        );

        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .vcpus
            .get(vcpu)
            .map(|vcpu| VCPU::into_current(&mut *vcpu.lock()));

        trace!("Switched to VCPU {} on Realm {}", vcpu, id);
        let ret = enter();

        exit();
        Ok(ret)
    }

    fn set_reg(&self, id: usize, vcpu: usize, register: usize, value: usize) -> Result<(), Error> {
        match register {
            0..=30 => {
                get_realm(id)
                    .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                    .lock()
                    .vcpus
                    .get(vcpu)
                    .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                    .lock()
                    .context
                    .gp_regs[register] = value as u64;
                Ok(())
            }
            31 => {
                get_realm(id)
                    .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                    .lock()
                    .vcpus
                    .get(vcpu)
                    .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                    .lock()
                    .context
                    .elr = value as u64;
                Ok(())
            }
            32 => {
                get_realm(id)
                    .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                    .lock()
                    .vcpus
                    .get(vcpu)
                    .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                    .lock()
                    .context
                    .spsr = value as u64;
                Ok(())
            }
            _ => Err(Error::RmiErrorInput),
        }?;
        Ok(())
    }

    fn get_reg(&self, id: usize, vcpu: usize, register: usize) -> Result<usize, Error> {
        match register {
            0..=30 => {
                let value = get_realm(id)
                    .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                    .lock()
                    .vcpus
                    .get(vcpu)
                    .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                    .lock()
                    .context
                    .gp_regs[register];
                Ok(value as usize)
            }
            31 => {
                let value = get_realm(id)
                    .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                    .lock()
                    .vcpus
                    .get(vcpu)
                    .ok_or(Error::RmiErrorOthers(NotExistVCPU))?
                    .lock()
                    .context
                    .elr;
                Ok(value as usize)
            }
            _ => Err(Error::RmiErrorInput),
        }
    }

    fn receive_gic_state_from_host(&self, id: usize, vcpu: usize, run: &Run) -> Result<(), Error> {
        let realm = get_realm(id).ok_or(Error::RmiErrorOthers(NotExistRealm))?;
        let locked_realm = realm.lock();
        let vcpu = locked_realm
            .vcpus
            .get(vcpu)
            .ok_or(Error::RmiErrorOthers(NotExistVCPU))?;
        let gic_state = &mut vcpu.lock().context.gic_state;
        let nr_lrs = GIC_FEATURES.nr_lrs;

        gic_state.ich_lr_el2[..nr_lrs].copy_from_slice(&unsafe { run.entry_gic_lrs() }[..nr_lrs]);
        gic_state.ich_hcr_el2 &= !ICH_HCR_EL2_NS_MASK;
        gic_state.ich_hcr_el2 |= (unsafe { run.entry_gic_hcr() } & ICH_HCR_EL2_NS_MASK);
        Ok(())
    }

    fn send_gic_state_to_host(&self, id: usize, vcpu: usize, run: &mut Run) -> Result<(), Error> {
        let realm = get_realm(id).ok_or(Error::RmiErrorOthers(NotExistRealm))?;
        let mut locked_realm = realm.lock();
        let vcpu = locked_realm
            .vcpus
            .get_mut(vcpu)
            .ok_or(Error::RmiErrorOthers(NotExistVCPU))?;
        let gic_state = &mut vcpu.lock().context.gic_state;
        let nr_lrs = GIC_FEATURES.nr_lrs;

        (&mut unsafe { run.exit_gic_lrs_mut() }[..nr_lrs])
            .copy_from_slice(&gic_state.ich_lr_el2[..nr_lrs]);
        unsafe {
            run.set_gic_misr(gic_state.ich_misr_el2);
            run.set_gic_vmcr(gic_state.ich_vmcr_el2);
            run.set_gic_hcr(
                gic_state.ich_hcr_el2 & (ICH_HCR_EL2_EOI_COUNT_MASK | ICH_HCR_EL2_NS_MASK),
            );
        }
        Ok(())
    }

    fn emulate_mmio(&self, id: usize, vcpu: usize, run: &Run) -> Result<(), Error> {
        let realm = get_realm(id).ok_or(Error::RmiErrorOthers(NotExistRealm))?;
        let mut locked_realm = realm.lock();
        let vcpu = locked_realm
            .vcpus
            .get_mut(vcpu)
            .ok_or(Error::RmiErrorOthers(NotExistVCPU))?;
        let context = &mut vcpu.lock().context;

        let flags = unsafe { run.entry_flags() };

        // Host has not completed emulation for an Emulatable Abort.
        if (flags & REC_ENTRY_FLAG_EMUL_MMIO) == 0 {
            return Ok(());
        }

        let esr_el2 = context.sys_regs.esr_el2;
        let esr = EsrEl2::new(esr_el2);
        let isv = esr.get_masked_value(EsrEl2::ISV);
        let ec = esr.get_masked_value(EsrEl2::EC);
        let wnr = esr.get_masked_value(EsrEl2::WNR);
        let rt = esr.get_masked_value(EsrEl2::SRT) as usize;

        if ec != ESR_EL2_EC_DATA_ABORT || isv == 0 {
            return Err(Error::RmiErrorRec);
        }

        // MMIO read case
        if wnr == 0 && rt != 31 {
            let sas = esr.get_masked_value(EsrEl2::SAS);
            let mask: u64 = match sas {
                0 => 0xff,                // byte
                1 => 0xffff,              // half-word
                2 => 0xffffffff,          // word
                3 => 0xffffffff_ffffffff, // double word
                _ => unreachable!(),      // SAS consists of two bits
            };
            let val = unsafe { run.entry_gpr(0)? } & mask;
            let sign_extended = esr.get_masked_value(EsrEl2::SSE);
            if sign_extended != 0 {
                // TODO
                unimplemented!();
            }
            context.gp_regs[rt] = val;
        }
        context.elr += 4;
        Ok(())
    }

    fn send_mmio_write(&self, id: usize, vcpu: usize, run: &mut Run) -> Result<(), Error> {
        let realm = get_realm(id).ok_or(Error::RmiErrorOthers(NotExistRealm))?;
        let mut locked_realm = realm.lock();
        let vcpu = locked_realm
            .vcpus
            .get_mut(vcpu)
            .ok_or(Error::RmiErrorOthers(NotExistVCPU))?;
        let context = &mut vcpu.lock().context;

        let esr_el2 = context.sys_regs.esr_el2;
        let esr = EsrEl2::new(esr_el2);
        let isv = esr.get_masked_value(EsrEl2::ISV);
        let ec = esr.get_masked_value(EsrEl2::EC);
        let wnr = esr.get_masked_value(EsrEl2::WNR);
        let rt = esr.get_masked_value(EsrEl2::SRT) as usize;

        // wnr == 1: caused by writing
        if ec != ESR_EL2_EC_DATA_ABORT || isv == 0 || wnr == 0 {
            return Ok(());
        }

        if rt == 31 {
            // xzr
            unsafe {
                run.set_gpr(0, 0)?;
            }
        } else {
            let sas = esr.get_masked_value(EsrEl2::SAS);
            let mask: u64 = match sas {
                0 => 0xff,                // byte
                1 => 0xffff,              // half-word
                2 => 0xffffffff,          // word
                3 => 0xffffffff_ffffffff, // double word
                _ => unreachable!(),      // SAS consists of two bits
            };
            let sign_extended = esr.get_masked_value(EsrEl2::SSE);
            if sign_extended != 0 {
                // TODO
                unimplemented!();
            }
            unsafe {
                run.set_gpr(0, context.gp_regs[rt] & mask)?;
            }
        }
        Ok(())
    }

    fn send_timer_state_to_host(&self, id: usize, vcpu: usize, run: &mut Run) -> Result<(), Error> {
        let realm = get_realm(id).ok_or(Error::RmiErrorOthers(NotExistRealm))?;
        let mut locked_realm = realm.lock();
        let vcpu = locked_realm
            .vcpus
            .get_mut(vcpu)
            .ok_or(Error::RmiErrorOthers(NotExistVCPU))?;
        let timer = &vcpu.lock().context.timer;

        unsafe {
            run.set_cntv_ctl(timer.cntv_ctl_el0);
            run.set_cntv_cval(timer.cntv_cval_el0 - timer.cntvoff_el2);
            run.set_cntp_ctl(timer.cntp_ctl_el0);
            run.set_cntp_cval(timer.cntp_cval_el0 - timer.cntpoff_el2);
        }
        Ok(())
    }

    fn realm_config(&self, id: usize, config_ipa: usize, ipa_bits: usize) -> Result<(), Error> {
        let res = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pa(GuestPhysAddr::from(config_ipa), RTT_PAGE_LEVEL);
        if let Some(pa) = res {
            let pa: usize = pa.into();
            unsafe { RealmConfig::init(pa, ipa_bits) };
            Ok(())
        } else {
            Err(Error::RmiErrorInput)
        }
    }

    fn rtt_create(
        &self,
        id: usize,
        rtt_addr: usize,
        ipa: usize,
        level: usize,
    ) -> Result<(), Error> {
        let mut rtt_granule = get_granule_if!(rtt_addr, GranuleState::Delegated)?;
        let s2tt = rtt_granule.content_mut::<RttPage>();

        let (parent_s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level - 1)
            .ok_or(Error::RmiErrorInput)?;

        if last_level != level - 1 {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let parent_s2tte = S2TTE::from(parent_s2tte as usize);
        let s2tt_len = s2tt.len();
        if parent_s2tte.is_unassigned() {
            if parent_s2tte.is_invalid_ripas() {
                panic!("invalid ripas");
            }
            let ripas = parent_s2tte.get_ripas();
            let mut new_s2tte = bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::UNASSIGNED);
            if ripas == invalid_ripas::EMPTY {
                new_s2tte |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::EMPTY);
            } else if ripas == invalid_ripas::RAM {
                new_s2tte |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::RAM);
            } else {
                panic!("Unexpected ripas:{}", ripas);
            }

            for i in 0..s2tt_len {
                if let Some(elem) = s2tt.get_mut(i) {
                    *elem = new_s2tte;
                }
            }
        } else if parent_s2tte.is_destroyed() {
            let new_s2tte = bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::DESTROYED);
            for i in 0..s2tt_len {
                if let Some(elem) = s2tt.get_mut(i) {
                    *elem = new_s2tte;
                }
            }
        } else if parent_s2tte.is_assigned() {
            let mut pa: usize = parent_s2tte
                .address(level - 1)
                .ok_or(Error::RmiErrorRtt(0))?
                .into(); //XXX: check this again
            let map_size = match level {
                3 => GRANULE_SIZE, // 4096
                2 => GRANULE_SIZE << S2TTE_STRIDE,
                1 => GRANULE_SIZE << S2TTE_STRIDE * 2,
                0 => GRANULE_SIZE << S2TTE_STRIDE * 3,
                _ => unreachable!(),
            };
            let mut flags = bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::ASSIGNED);
            flags |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::EMPTY);
            let mut new_s2tte = pa as u64 | flags;
            for i in 0..s2tt_len {
                if let Some(elem) = s2tt.get_mut(i) {
                    *elem = new_s2tte;
                }
                pa += map_size;
                new_s2tte = pa as u64 | flags;
            }
        } else if parent_s2tte.is_valid(level - 1, false) {
            unimplemented!();
        } else if parent_s2tte.is_valid(level - 1, true) {
            unimplemented!();
        } else if parent_s2tte.is_table(level - 1) {
            return Err(Error::RmiErrorRtt(level - 1));
        } else {
            panic!("Unexpected s2tte value:{:X}", parent_s2tte.get());
        }

        set_granule(&mut rtt_granule, GranuleState::RTT)?;

        let parent_s2tte = rtt_addr as u64 | bits_in_reg(S2TTE::DESC_TYPE, desc_type::L012_TABLE);
        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level - 1, parent_s2tte)?;

        // The below is added to avoid a fault regarding the RTT entry
        PageTable::get_ref().map(rtt_addr, true);

        Ok(())
    }

    fn rtt_destroy(&self, rd: &Rd, rtt_addr: usize, ipa: usize, level: usize) -> Result<(), Error> {
        let id = rd.id();
        let (parent_s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level - 1)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again

        if last_level != level - 1 {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let parent_s2tte = S2TTE::from(parent_s2tte as usize);
        if !parent_s2tte.is_table(level - 1) {
            return Err(Error::RmiErrorRtt(level - 1));
        }

        let pa_table = parent_s2tte
            .address(RTT_PAGE_LEVEL)
            .ok_or(Error::RmiErrorInput)?
            .try_into()
            .or(Err(Error::RmiErrorInput))?;
        if rtt_addr != pa_table {
            return Err(Error::RmiErrorInput);
        }

        let mut g_rtt = get_granule_if!(rtt_addr, GranuleState::RTT)?;

        let parent_s2tte;
        if rd.addr_in_par(ipa) {
            parent_s2tte = bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::DESTROYED);
        } else {
            parent_s2tte = INVALID_UNPROTECTED;
        }

        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level - 1, parent_s2tte)?;

        set_granule(&mut g_rtt, GranuleState::Delegated)?;
        Ok(())
    }

    fn rtt_init_ripas(&self, id: usize, ipa: usize, level: usize) -> Result<(), Error> {
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again

        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let s2tte = S2TTE::from(s2tte as usize);
        if s2tte.is_table(level) || !s2tte.is_unassigned() {
            return Err(Error::RmiErrorRtt(level));
        }

        let mut new_s2tte = s2tte.get();
        new_s2tte |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::RAM);

        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;

        Ok(())
    }

    fn rtt_get_ripas(&self, id: usize, ipa: usize, level: usize) -> Result<u64, Error> {
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?;

        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let s2tte = S2TTE::from(s2tte as usize);
        if s2tte.is_destroyed() {
            error!("The s2tte is destroyed: {:x}", s2tte.get());
            return Err(Error::RmiErrorRtt(last_level));
        }
        Ok(s2tte.get_ripas())
    }

    fn rtt_read_entry(&self, id: usize, ipa: usize, level: usize) -> Result<[usize; 4], Error> {
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?;

        let r1 = last_level;
        let (mut r2, mut r3, mut r4) = (0, 0, 0);

        let s2tte = S2TTE::from(s2tte as usize);

        if s2tte.is_unassigned() {
            let ripas = s2tte.get_masked_value(S2TTE::INVALID_RIPAS);
            r2 = rtt_entry_state::RMI_UNASSIGNED;
            r4 = ripas as usize;
        } else if s2tte.is_destroyed() {
            r2 = rtt_entry_state::RMI_DESTROYED;
        } else if s2tte.is_assigned() {
            r2 = rtt_entry_state::RMI_ASSIGNED;
            r3 = s2tte
                .address(last_level)
                .ok_or(Error::RmiErrorRtt(0))?
                .into(); //XXX: check this again
            r4 = invalid_ripas::EMPTY as usize;
        } else if s2tte.is_valid(last_level, false) {
            r2 = rtt_entry_state::RMI_ASSIGNED;
            r3 = s2tte
                .address(last_level)
                .ok_or(Error::RmiErrorRtt(0))?
                .into(); //XXX: check this again
            r4 = invalid_ripas::RAM as usize;
        } else if s2tte.is_valid(last_level, true) {
            r2 = rtt_entry_state::RMI_VALID_NS;
            let addr_mask = match level {
                1 => S2TTE::ADDR_L1_PAGE,
                2 => S2TTE::ADDR_L2_PAGE,
                3 => S2TTE::ADDR_L3_PAGE,
                _ => {
                    return Err(Error::RmiErrorRtt(0)); //XXX: check this again
                }
            };
            let mask = addr_mask | S2TTE::MEMATTR | S2TTE::AP | S2TTE::SH;
            r3 = (s2tte.get() & mask) as usize;
        } else if s2tte.is_table(last_level) {
            r2 = rtt_entry_state::RMI_TABLE;
            r3 = s2tte
                .address(RTT_PAGE_LEVEL)
                .ok_or(Error::RmiErrorRtt(0))?
                .into(); //XXX: check this again
        } else {
            error!("Unexpected S2TTE value retrieved!");
        }
        Ok([r1, r2, r3, r4])
    }

    fn rtt_map_unprotected(
        &self,
        rd: &Rd,
        ipa: usize,
        level: usize,
        host_s2tte: usize,
    ) -> Result<(), Error> {
        if rd.addr_in_par(ipa) {
            return Err(Error::RmiErrorInput);
        }

        let id = rd.id();
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again

        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let s2tte = S2TTE::from(s2tte as usize);

        if !s2tte.is_unassigned() {
            return Err(Error::RmiErrorRtt(level));
        }

        let mut new_s2tte = host_s2tte as u64;
        if level == RTT_PAGE_LEVEL {
            new_s2tte |= bits_in_reg(S2TTE::NS, 1)
                | bits_in_reg(S2TTE::XN, 1)
                | bits_in_reg(S2TTE::AF, 1)
                | bits_in_reg(S2TTE::DESC_TYPE, desc_type::L3_PAGE);
        } else {
            new_s2tte |= bits_in_reg(S2TTE::NS, 1)
                | bits_in_reg(S2TTE::XN, 1)
                | bits_in_reg(S2TTE::AF, 1)
                | bits_in_reg(S2TTE::DESC_TYPE, desc_type::L012_BLOCK);
        }

        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;

        Ok(())
    }

    fn rtt_unmap_unprotected(&self, id: usize, ipa: usize, level: usize) -> Result<(), Error> {
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again

        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let s2tte = S2TTE::from(s2tte as usize);
        if !s2tte.is_valid(level, true) {
            return Err(Error::RmiErrorRtt(level));
        }

        let new_s2tte: u64 = INVALID_UNPROTECTED;

        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;

        //TODO: add page/block invalidation

        Ok(())
    }

    fn make_shared(&self, id: usize, ipa: usize, level: usize) -> Result<(), Error> {
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again
        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level)); //XXX: check this again
        }

        let s2tte = S2TTE::from(s2tte as usize);

        // Reference (tf-rmm)      : smc_rtt_set_ripas() in runtime/rmi/rtt.c
        //           (realm-linux) : __set_memory_encrypted() in arch/arm64/mm/pageattr.c
        //           (nw-linux)    : set_ipa_state() and kvm_realm_unmap_range() in arch/arm64/kvm/rme.c
        //           (rmm-spec)    : Figure D2.1 Realm shared memory protocol flow
        if s2tte.is_valid(level, false) {
            // the case for ipa's range 0x8840_0000 - in realm-linux booting
            let pa: usize = s2tte.address(level).ok_or(Error::RmiErrorRtt(0))?.into(); //XXX: check this again
            let mut flags = 0;
            flags |= bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::ASSIGNED);
            flags |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::EMPTY);
            let new_s2tte = pa as u64 | flags;

            get_realm(id)
                .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                .lock()
                .page_table
                .lock()
                .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;
        } else if s2tte.is_unassigned() || s2tte.is_assigned() {
            let pa: usize = s2tte.address(level).ok_or(Error::RmiErrorRtt(0))?.into(); //XXX: check this again
            let flags = bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::EMPTY);
            let new_s2tte = pa as u64 | flags;

            get_realm(id)
                .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                .lock()
                .page_table
                .lock()
                .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;
        }

        Ok(())
    }

    fn make_exclusive(&self, id: usize, ipa: usize, level: usize) -> Result<(), Error> {
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again
        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level)); //XXX: check this again
        }

        let s2tte = S2TTE::from(s2tte as usize);

        if s2tte.is_valid(level, false) {
            // This condition is added with no-op for handling the `else` case
        } else if s2tte.is_unassigned() || s2tte.is_assigned() {
            let flags = bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::RAM);
            let new_s2tte = s2tte.get() | flags;

            get_realm(id)
                .ok_or(Error::RmiErrorOthers(NotExistRealm))?
                .lock()
                .page_table
                .lock()
                .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;
        } else {
            return Err(Error::RmiErrorRtt(level)); //XXX: check this again
        }

        Ok(())
    }

    fn data_create(&self, id: usize, ipa: usize, target_pa: usize) -> Result<(), Error> {
        let level = RTT_PAGE_LEVEL;
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again

        if level != last_level {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let s2tte = S2TTE::from(s2tte as usize);
        if !s2tte.is_unassigned() {
            return Err(Error::RmiErrorRtt(RTT_PAGE_LEVEL));
        }

        let mut new_s2tte = target_pa as u64;
        if s2tte.is_invalid_ripas() {
            panic!("invalid ripas");
        }
        let ripas = s2tte.get_ripas();
        if ripas == invalid_ripas::EMPTY {
            new_s2tte |= bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::ASSIGNED);
            new_s2tte |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::EMPTY);
        } else if ripas == invalid_ripas::RAM {
            // S2TTE_PAGE  : S2TTE_ATTRS | S2TTE_L3_PAGE
            new_s2tte |= bits_in_reg(S2TTE::DESC_TYPE, desc_type::L3_PAGE);
            // S2TTE_ATTRS : S2TTE_MEMATTR_FWB_NORMAL_WB | S2TTE_AP_RW | S2TTE_SH_IS | S2TTE_AF
            new_s2tte |= bits_in_reg(S2TTE::MEMATTR, attribute::NORMAL_FWB);
            new_s2tte |= bits_in_reg(S2TTE::AP, permission::RW);
            new_s2tte |= bits_in_reg(S2TTE::SH, shareable::INNER);
            new_s2tte |= bits_in_reg(S2TTE::AF, 1);
        } else {
            panic!("Unexpected ripas: {}", ripas);
        }

        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;

        Ok(())
    }

    fn data_destroy(&self, id: usize, ipa: usize) -> Result<usize, Error> {
        let level = RTT_PAGE_LEVEL;
        let (s2tte, last_level) = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte(GuestPhysAddr::from(ipa), level)
            .ok_or(Error::RmiErrorRtt(0))?; //XXX: check this again

        if last_level != level {
            return Err(Error::RmiErrorRtt(last_level));
        }

        let s2tte = S2TTE::from(s2tte as usize);

        let valid = s2tte.is_valid(last_level, false);
        if !valid && !s2tte.is_assigned() {
            return Err(Error::RmiErrorRtt(RTT_PAGE_LEVEL));
        }

        let pa = s2tte
            .address(last_level)
            .ok_or(Error::RmiErrorRtt(0))?
            .into(); //XXX: check this again

        let mut flags = 0 as u64;
        if valid {
            flags |= bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::DESTROYED);
        } else {
            flags |= bits_in_reg(S2TTE::INVALID_HIPAS, invalid_hipas::UNASSIGNED);
            flags |= bits_in_reg(S2TTE::INVALID_RIPAS, invalid_ripas::EMPTY);
        }
        let new_s2tte = flags;
        get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pte_set(GuestPhysAddr::from(ipa), level, new_s2tte)?;

        Ok(pa)
    }

    fn attest(&self, id: usize, attest_ipa: usize, _attest_token: &[u8]) -> Result<usize, Error> {
        let res = get_realm(id)
            .ok_or(Error::RmiErrorOthers(NotExistRealm))?
            .lock()
            .page_table
            .lock()
            .ipa_to_pa(GuestPhysAddr::from(attest_ipa), 3);

        let pa: usize = match res {
            Some(pa) => pa.into(),
            None =>   return Err(Error::RmiErrorInput)
        };

        let dummy_token = [
            0xd9, 0x01, 0x8f, 0xa2, 0x19, 0xac, 0xca, 0x59, 0x04, 0x96, 0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59, 0x04, 0x29, 0xa9, 0x0a, 0x58,
            0x20, 0x53, 0x53, 0xe0, 0x30, 0x67, 0x15, 0x45, 0x7c, 0xb8, 0xc8, 0x30, 0x74, 0xa8, 0xb7, 0x88, 0x88, 0xc9, 0x20, 0xb9, 0x31, 0x5e, 0x35, 0xd9,
            0xec, 0x95, 0x23, 0x43, 0x4b, 0xed, 0x44, 0x30, 0x76, 0x19, 0x01, 0x00, 0x58, 0x21, 0x01, 0x1b, 0xe9, 0xc3, 0x36, 0xd7, 0xa7, 0x0b, 0x66, 0x13,
            0x82, 0x93, 0x4a, 0x26, 0x01, 0x92, 0x35, 0x1a, 0xc6, 0x1d, 0x24, 0xe2, 0x0d, 0x88, 0x2f, 0x49, 0x4a, 0xbe, 0xe8, 0x7f, 0x8a, 0x1e, 0x98, 0x19,
            0x01, 0x09, 0x78, 0x1c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x43, 0x41, 0x2d, 0x53,
            0x53, 0x44, 0x2f, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x19, 0x09, 0x5b, 0x19, 0x30, 0x00, 0x19, 0x09, 0x5c, 0x58, 0x20, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0x19, 0x09, 0x5f, 0x89, 0xa5, 0x01, 0x63, 0x42, 0x4c, 0x31, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58,
            0x20, 0x69, 0x7d, 0xe4, 0x40, 0x7d, 0xae, 0x45, 0xc0, 0x75, 0x06, 0xd1, 0xf0, 0x0b, 0x3d, 0xbf, 0x5c, 0xe1, 0xdb, 0x41, 0xf6, 0x9e, 0x17, 0x50,
            0xa3, 0x11, 0xf9, 0x1d, 0x21, 0x3e, 0x11, 0x98, 0x89, 0x04, 0x65, 0x30, 0x2e, 0x31, 0x2e, 0x30, 0x05, 0x58, 0x20, 0xc6, 0xc3, 0x2a, 0x95, 0x7d,
            0xf4, 0xc6, 0x69, 0x8c, 0x55, 0x0b, 0x69, 0x5d, 0x02, 0x2e, 0xd5, 0x18, 0x0c, 0xae, 0x71, 0xf8, 0xb4, 0x9c, 0xbb, 0x75, 0xe6, 0x06, 0x1c, 0x2e,
            0xf4, 0x97, 0xe1, 0xa5, 0x01, 0x63, 0x42, 0x4c, 0x32, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x35, 0x31, 0x32, 0x02, 0x58, 0x40, 0x8e, 0x17, 0x5a,
            0x1d, 0xcd, 0x79, 0xb8, 0xb5, 0x1c, 0xe9, 0xe2, 0x59, 0xc2, 0x56, 0x83, 0x05, 0xb7, 0x3f, 0x5f, 0x26, 0xf5, 0x67, 0x3a, 0x8c, 0xf7, 0x81, 0xa9,
            0x45, 0x98, 0xe4, 0x4f, 0x67, 0xfd, 0xf4, 0x92, 0x68, 0x69, 0xee, 0x76, 0x67, 0xe9, 0x12, 0x0b, 0x5c, 0x1b, 0x97, 0x62, 0x5c, 0xc9, 0x6d, 0x34,
            0x7c, 0x23, 0xce, 0x3c, 0x5f, 0x76, 0x3b, 0xf1, 0xd9, 0xb5, 0x47, 0x81, 0xf6, 0x04, 0x67, 0x31, 0x2e, 0x39, 0x2e, 0x30, 0x2b, 0x30, 0x05, 0x58,
            0x20, 0xa0, 0x64, 0xb1, 0xad, 0x60, 0xfa, 0x18, 0x33, 0x94, 0xdd, 0xa5, 0x78, 0x91, 0x35, 0x7f, 0x97, 0x2e, 0x4f, 0xe7, 0x22, 0x78, 0x2a, 0xdf,
            0xf1, 0x85, 0x4c, 0x8b, 0x2a, 0x14, 0x2c, 0x04, 0x10, 0xa5, 0x01, 0x69, 0x46, 0x57, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x06, 0x67, 0x73,
            0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0xd2, 0x24, 0x49, 0xeb, 0x85, 0x3a, 0xa1, 0xf6, 0xfa, 0x8c, 0xca, 0x74, 0xa5, 0xba, 0x4f,
            0xd0, 0xdf, 0xab, 0xbe, 0x31, 0x35, 0xc6, 0x72, 0x94, 0x7e, 0x69, 0x69, 0xd2, 0x02, 0x71, 0xb4, 0xa4, 0x04, 0x60, 0x05, 0x58, 0x20, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x01, 0x6c, 0x54, 0x42, 0x5f, 0x46, 0x57, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x06, 0x67, 0x73,
            0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0xc7, 0xf9, 0x9e, 0x45, 0xbb, 0x76, 0xf3, 0x3f, 0xfa, 0x37, 0x27, 0x44, 0x88, 0xfc, 0x00,
            0x19, 0xab, 0x5b, 0xa5, 0x26, 0xa2, 0x7b, 0x29, 0x1e, 0x2b, 0x14, 0xe1, 0x76, 0x2a, 0xa0, 0xc1, 0xeb, 0x04, 0x60, 0x05, 0x58, 0x20, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x01, 0x64, 0x42, 0x4c, 0x5f, 0x32, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58,
            0x20, 0x2b, 0xb8, 0x72, 0xbf, 0x8b, 0x83, 0x06, 0xd7, 0xac, 0x8d, 0x32, 0x9e, 0xfe, 0x51, 0x34, 0x90, 0x67, 0xc3, 0x2d, 0xe5, 0x38, 0x5f, 0xa1,
            0x3c, 0x20, 0x22, 0x6e, 0x1d, 0xdc, 0x7f, 0x24, 0x37, 0x04, 0x60, 0x05, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x01,
            0x6d, 0x53, 0x45, 0x43, 0x55, 0x52, 0x45, 0x5f, 0x52, 0x54, 0x5f, 0x45, 0x4c, 0x33, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02,
            0x58, 0x20, 0xa0, 0x8a, 0x57, 0xd7, 0x21, 0x2a, 0x20, 0x73, 0xa0, 0xdd, 0x6a, 0x58, 0xef, 0xd3, 0x3a, 0xb9, 0xba, 0x23, 0xa6, 0x8e, 0x3d, 0xcc,
            0xd4, 0xb0, 0xb2, 0xaf, 0xcd, 0x7a, 0xf4, 0x28, 0xae, 0x67, 0x04, 0x60, 0x05, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5,
            0x01, 0x69, 0x48, 0x57, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0xaf,
            0xcf, 0xc2, 0x71, 0x36, 0x29, 0xf1, 0xf4, 0x63, 0x9b, 0xe2, 0xe0, 0xa7, 0x4b, 0x44, 0xaa, 0xc1, 0xe4, 0x4f, 0xb1, 0x84, 0x49, 0x6b, 0x12, 0x88,
            0xa6, 0x76, 0xa0, 0x06, 0x7c, 0x47, 0x50, 0x04, 0x60, 0x05, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x01, 0x6d, 0x53,
            0x4f, 0x43, 0x5f, 0x46, 0x57, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20,
            0xb5, 0x96, 0x80, 0xed, 0xc2, 0x21, 0x01, 0x68, 0x63, 0x00, 0xd9, 0xc4, 0xcb, 0x79, 0x28, 0x2f, 0xaa, 0x63, 0x5c, 0x0a, 0x3a, 0x3c, 0x6f, 0xd0,
            0xc3, 0x73, 0x5a, 0xa1, 0xff, 0xa4, 0x81, 0x8f, 0x04, 0x60, 0x05, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x01, 0x63,
            0x52, 0x4d, 0x4d, 0x06, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0x6d, 0x3a, 0xbd, 0xe5, 0xa5, 0x5f, 0x98, 0xd7, 0x81,
            0x15, 0x57, 0xa3, 0x64, 0x8a, 0x0b, 0xa7, 0xa1, 0x67, 0x1d, 0xf5, 0xc6, 0x63, 0x45, 0xca, 0xb3, 0xd8, 0x52, 0x03, 0x8d, 0x5f, 0x95, 0x15, 0x04,
            0x60, 0x05, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x09, 0x60, 0x73, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
            0x68, 0x61, 0x74, 0x65, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x19, 0x09, 0x61, 0x44, 0xef, 0xbe, 0xad, 0xde, 0x19, 0x09, 0x62, 0x67, 0x73,
            0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x58, 0x60, 0x50, 0xf4, 0xe0, 0x16, 0x49, 0x01, 0xcc, 0xeb, 0xf0, 0x93, 0xdf, 0x82, 0x20, 0x07, 0x82, 0xf0,
            0x5d, 0x26, 0x66, 0x20, 0xab, 0x48, 0xac, 0x4c, 0x63, 0x99, 0x40, 0xc6, 0xb4, 0x4f, 0xb2, 0xd0, 0xbe, 0xed, 0xe0, 0x89, 0xec, 0x1d, 0x75, 0x9e,
            0xa8, 0x51, 0x7b, 0xd0, 0xf1, 0x36, 0x4f, 0x1d, 0x27, 0xaa, 0x8f, 0x27, 0x7a, 0x66, 0x93, 0x82, 0xb2, 0xd1, 0x99, 0x82, 0x12, 0xd2, 0x47, 0xbc,
            0x44, 0x2f, 0x19, 0xa2, 0xc0, 0x65, 0x3f, 0xa9, 0x27, 0x9b, 0x24, 0x10, 0x31, 0x8d, 0x8c, 0xcb, 0xc5, 0x15, 0x70, 0x78, 0x13, 0x9a, 0x5f, 0x93,
            0xd8, 0x99, 0xee, 0x16, 0xaf, 0x27, 0x47, 0x7a, 0x19, 0xac, 0xd1, 0x59, 0x02, 0x23, 0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59, 0x01,
            0xb6, 0xa7, 0x0a, 0x58, 0x40, 0x4a, 0x48, 0x87, 0x7b, 0xc1, 0xb8, 0x86, 0x30, 0xf6, 0x76, 0x99, 0x59, 0x7a, 0xde, 0x8e, 0x65, 0xd0, 0xa8, 0xaa,
            0xf7, 0x1c, 0xe2, 0xe3, 0x0b, 0xb8, 0xf0, 0x47, 0xb0, 0x1d, 0x77, 0xd5, 0xfb, 0xb8, 0x4b, 0x30, 0x3f, 0x6d, 0xd9, 0xd8, 0x63, 0x8d, 0xc0, 0x05,
            0x13, 0x9b, 0x01, 0xc3, 0xb7, 0xc6, 0xd7, 0x33, 0xf5, 0xa1, 0xb7, 0x57, 0x1f, 0xec, 0x95, 0x95, 0x9e, 0xd7, 0x02, 0x24, 0xf2, 0x19, 0xac, 0xcb,
            0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xac, 0xcd, 0x58, 0x61, 0x04,
            0x15, 0x8e, 0x24, 0xb1, 0x2c, 0x92, 0x93, 0x37, 0xcd, 0x4e, 0x22, 0xb9, 0xfe, 0xfd, 0x06, 0xc8, 0xd8, 0xf2, 0xb5, 0x72, 0x5b, 0xd5, 0x8d, 0x33,
            0x6f, 0x44, 0x02, 0x10, 0x23, 0xe3, 0x59, 0x0b, 0x4c, 0xc9, 0xc3, 0x5f, 0x98, 0x60, 0x79, 0xe3, 0x82, 0x32, 0x37, 0xcf, 0xfa, 0x51, 0x05, 0xd6,
            0x8b, 0x2f, 0x00, 0xf7, 0x1e, 0xbf, 0xb4, 0xa7, 0x6d, 0x1d, 0x87, 0x76, 0x98, 0x2b, 0x5c, 0x33, 0x2e, 0x11, 0x93, 0x97, 0x0c, 0x3d, 0x67, 0x49,
            0x89, 0x4b, 0x06, 0x88, 0xb5, 0x6d, 0x8f, 0xf4, 0x18, 0x77, 0x6b, 0x76, 0x2e, 0xe6, 0x4b, 0x8d, 0xf7, 0x4f, 0x25, 0x9f, 0x57, 0x2f, 0x0b, 0x98,
            0x19, 0xac, 0xcc, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x19, 0xac, 0xd0, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x19, 0xac,
            0xce, 0x58, 0x20, 0x59, 0x58, 0x79, 0x44, 0xeb, 0xd7, 0xba, 0xad, 0xb8, 0xd4, 0x79, 0x0b, 0x55, 0x51, 0x0c, 0x25, 0x18, 0x1c, 0x83, 0x98, 0x1a,
            0x92, 0xc6, 0x97, 0x0d, 0x70, 0x80, 0xa0, 0xcf, 0x85, 0xd3, 0xbe, 0x19, 0xac, 0xcf, 0x84, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x60, 0x57, 0x1d, 0xb1, 0xc9, 0xa9, 0x91, 0x2b, 0x84, 0x83, 0xfa, 0x23, 0xfc, 0x2d, 0x4e, 0x33,
            0xbe, 0xfe, 0x55, 0x43, 0xb5, 0x06, 0x74, 0xfb, 0xf9, 0xef, 0x5a, 0xa1, 0x2b, 0x9a, 0x40, 0x68, 0x60, 0x86, 0x21, 0x81, 0xba, 0xc7, 0x1c, 0xb5,
            0x49, 0xe7, 0xcf, 0xe7, 0x23, 0x6e, 0xc3, 0xfa, 0x4a, 0x83, 0xb8, 0x9f, 0x8f, 0x9a, 0xe7, 0xa0, 0xac, 0x65, 0xf2, 0x85, 0xd5, 0x3d, 0x49, 0xb7,
            0x08, 0x19, 0x9e, 0x4a, 0xee, 0xee, 0x2b, 0x73, 0xaa, 0xfa, 0xc7, 0xac, 0xd2, 0x89, 0x87, 0x8c, 0xab, 0x1f, 0x2a, 0xb4, 0x6a, 0x49, 0x21, 0x33,
            0x2b, 0x90, 0xd3, 0xf3, 0xf7, 0x28, 0x3d, 0x5c, 0x14
        ];
        unsafe {
            let pa_ptr = pa as *mut u8;
            core::ptr::copy(dummy_token.as_ptr(), pa_ptr, dummy_token.len());
        }

        Ok(dummy_token.len())
    }

}

impl crate::rsi::Interface for RsiHandle {
    fn measurement_read(
        &self,
        realmid: usize,
        index: usize,
        out: &mut crate::measurement::Measurement,
    ) -> Result<(), crate::rsi::error::Error> {
        let realm_lock = get_realm(realmid).ok_or(RsiError::RealmDoesNotExists)?;

        let mut realm = realm_lock.lock();

        let measurement = realm
            .measurements
            .iter_mut()
            .nth(index)
            .ok_or(RsiError::InvalidMeasurementIndex)?;

        out.as_mut_slice().copy_from_slice(measurement.as_slice());
        Ok(())
    }

    fn measurement_extend(
        &self,
        realmid: usize,
        index: usize,
        f: impl Fn(&mut crate::measurement::Measurement) -> Result<(), MeasurementError>,
    ) -> Result<(), crate::rsi::error::Error> {
        let realm_lock = get_realm(realmid).ok_or(RsiError::RealmDoesNotExists)?;

        let mut realm = realm_lock.lock();

        let measurement = realm
            .measurements
            .iter_mut()
            .nth(index)
            .ok_or(RsiError::InvalidMeasurementIndex)?;

        f(measurement)?;
        Ok(())
    }
}
