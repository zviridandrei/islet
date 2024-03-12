extern crate alloc;

use super::realm::{rd::State, Rd};
use super::rec::Rec;
use crate::event::Mainloop;
use crate::granule::{
    is_granule_aligned, is_not_in_realm, set_granule, GranuleState, GRANULE_SHIFT, GRANULE_SIZE,
};
use crate::host::pointer::Pointer as HostPointer;
use crate::host::DataPage;
use crate::listen;
use crate::measurement::HashContext;
use crate::realm::mm::stage2_tte::S2TTE;
use crate::rmi;
use crate::rmi::error::Error;
use crate::{get_granule, get_granule_if, set_state_and_get_granule};

pub const RTT_MIN_BLOCK_LEVEL: usize = 2;
pub const RTT_PAGE_LEVEL: usize = 3;
pub const S2TTE_STRIDE: usize = GRANULE_SHIFT - 3;
//pub const S2TTES_PER_S2TT: usize = 1 << S2TTE_STRIDE;

const RIPAS_EMPTY: u64 = 0;
const RIPAS_RAM: u64 = 1;

fn level_to_size(level: usize) -> u64 {
    // TODO: get the translation granule from src/armv9
    match level {
        0 => 512 << 30, // 512GB
        1 => 1 << 30,   // 1GB
        2 => 2 << 20,   // 2MB
        3 => 1 << 12,   // 4KB
        _ => 0,
    }
}

fn is_valid_rtt_cmd(ipa: usize, level: usize, ipa_bits: usize) -> bool {
    if level > RTT_PAGE_LEVEL {
        return false;
    }

    if ipa >= realm_ipa_size(ipa_bits) {
        return false;
    }
    let mask = match level {
        0 => S2TTE::ADDR_L0_PAGE,
        1 => S2TTE::ADDR_L1_PAGE,
        2 => S2TTE::ADDR_L2_PAGE,
        3 => S2TTE::ADDR_L3_PAGE,
        _ => unreachable!(),
    };
    if ipa & mask as usize != ipa {
        return false;
    }
    true
}

pub fn set_event_handler(mainloop: &mut Mainloop) {
    listen!(mainloop, rmi::RTT_CREATE, |arg, _ret, _rmm| {
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rtt_addr = arg[1];
        let rd = rd_granule.content::<Rd>();
        let ipa = arg[2];
        let level = arg[3];

        let min_level = rd.s2_starting_level() as usize + 1;

        if (level < min_level)
            || (level > RTT_PAGE_LEVEL)
            || !is_valid_rtt_cmd(ipa, level - 1, rd.ipa_bits())
        {
            return Err(Error::RmiErrorInput);
        }
        if rtt_addr == arg[0] {
            return Err(Error::RmiErrorInput);
        }
        crate::rtt::create(rd.id(), rtt_addr, ipa, level)?;
        Ok(())
    });

    listen!(mainloop, rmi::RTT_DESTROY, |arg, ret, _rmm| {
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let ipa = arg[1];
        let level = arg[2];

        let min_level = rd.s2_starting_level() as usize + 1;

        if (level < min_level)
            || (level > RTT_PAGE_LEVEL)
            || !is_valid_rtt_cmd(ipa, level - 1, rd.ipa_bits())
        {
            return Err(Error::RmiErrorInput);
        }
        let (ipa, walk_top) = crate::rtt::destroy(rd, ipa, level)?;
        ret[1] = ipa;
        ret[2] = walk_top;
        Ok(())
    });

    listen!(mainloop, rmi::RTT_INIT_RIPAS, |arg, ret, _rmm| {
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let base = arg[1];
        let top = arg[2];

        if rd.state() != State::New {
            return Err(Error::RmiErrorRealm(0));
        }

        if top <= base {
            return Err(Error::RmiErrorInput);
        }
        if !is_valid_rtt_cmd(base, RTT_PAGE_LEVEL, rd.ipa_bits())
            || !is_valid_rtt_cmd(top, RTT_PAGE_LEVEL, rd.ipa_bits())
            || !is_protected_ipa(base, rd.ipa_bits())
            || !is_protected_ipa(top - GRANULE_SIZE, rd.ipa_bits())
        {
            return Err(Error::RmiErrorInput);
        }
        let res = crate::rtt::init_ripas(rd.id(), base, top)?;
        ret[1] = res; //This is walk_top

        //TODO: Update the function according to the changes from eac5
        HashContext::new(rd)?.measure_ripas_granule(base, RTT_PAGE_LEVEL as u8)?;
        Ok(())
    });

    listen!(mainloop, rmi::RTT_SET_RIPAS, |arg, _ret, _rmm| {
        let ipa = arg[2];
        let level = arg[3];
        let ripas = arg[4];

        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let mut rec_granule = get_granule_if!(arg[1], GranuleState::Rec)?;
        let rec = rec_granule.content_mut::<Rec<'_>>();

        let mut prot = rmi::MapProt::new(0);
        match ripas as u64 {
            RIPAS_EMPTY => prot.set_bit(rmi::MapProt::NS_PAS),
            RIPAS_RAM => { /* do nothing: ripas ram by default */ }
            _ => {
                warn!("Unknown RIPAS:{}", ripas);
                return Err(Error::RmiErrorInput); //XXX: check this again
            }
        }

        if rec.ripas_state() != ripas as u8 {
            return Err(Error::RmiErrorInput);
        }

        if rec.ripas_addr() != ipa as u64 {
            return Err(Error::RmiErrorInput);
        }

        let map_size = level_to_size(level);
        if ipa as u64 + map_size > rec.ripas_end() {
            return Err(Error::RmiErrorInput);
        }

        if ripas as u64 == RIPAS_EMPTY {
            crate::rtt::make_shared(rd.id(), ipa, level)?;
        } else if ripas as u64 == RIPAS_RAM {
            crate::rtt::make_exclusive(rd.id(), ipa, level)?;
        } else {
            unreachable!();
        }
        rec.inc_ripas_addr(map_size);
        Ok(())
    });

    listen!(mainloop, rmi::RTT_READ_ENTRY, |arg, ret, _rmm| {
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let ipa = arg[1];
        let level = arg[2];
        if !is_valid_rtt_cmd(ipa, level, rd.ipa_bits()) {
            return Err(Error::RmiErrorInput);
        }

        let res = crate::rtt::read_entry(rd.id(), ipa, level)?;
        ret[1..5].copy_from_slice(&res[0..4]);

        Ok(())
    });

    listen!(mainloop, rmi::DATA_CREATE, |arg, _ret, rmm| {
        // target_pa: location where realm data is created.
        let rd = arg[0];
        let target_pa = arg[1];
        let ipa = arg[2];
        let src_pa = arg[3];
        let flags = arg[4];

        if target_pa == rd || target_pa == src_pa || rd == src_pa {
            return Err(Error::RmiErrorInput);
        }

        // rd granule lock
        let rd_granule = get_granule_if!(rd, GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let realm_id = rd.id();

        // Make sure DATA_CREATE is only processed
        // when the realm is in its New state.
        if !rd.at_state(State::New) {
            return Err(Error::RmiErrorRealm(0));
        }

        validate_ipa(ipa, rd.ipa_bits())?;

        if !is_not_in_realm(src_pa) {
            return Err(Error::RmiErrorInput);
        };

        // data granule lock for the target page
        let mut target_page_granule = get_granule_if!(target_pa, GranuleState::Delegated)?;
        let target_page = target_page_granule.content_mut::<DataPage>();
        rmm.page_table.map(target_pa, true);

        // read src page
        let src_page = copy_from_host_or_ret!(DataPage, src_pa);

        HashContext::new(rd)?.measure_data_granule(&src_page, ipa, flags)?;

        // 3. copy src to _data
        *target_page = src_page;

        // 4. map ipa to taget_pa in S2 table
        crate::rtt::data_create(realm_id, ipa, target_pa, false)?;

        set_granule(&mut target_page_granule, GranuleState::Data)?;
        Ok(())
    });

    listen!(mainloop, rmi::DATA_CREATE_UNKNOWN, |arg, _ret, rmm| {
        // rd granule lock
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let realm_id = rd.id();

        // target_phys: location where realm data is created.
        let target_pa = arg[1];
        let ipa = arg[2];
        if target_pa == arg[0] {
            return Err(Error::RmiErrorInput);
        }

        validate_ipa(ipa, rd.ipa_bits())?;

        // 0. Make sure granule state can make a transition to DATA
        // data granule lock for the target page
        let mut target_page_granule = get_granule_if!(target_pa, GranuleState::Delegated)?;
        rmm.page_table.map(target_pa, true);

        // 1. map ipa to target_pa in S2 table
        crate::rtt::data_create(realm_id, ipa, target_pa, true)?;

        // TODO: 2. perform measure
        // L0czek - not needed here see: tf-rmm/runtime/rmi/rtt.c:883
        set_granule(&mut target_page_granule, GranuleState::Data)?;
        Ok(())
    });

    listen!(mainloop, rmi::DATA_DESTROY, |arg, ret, _rmm| {
        // rd granule lock
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let realm_id = rd.id();
        let ipa = arg[1];

        if !is_protected_ipa(ipa, rd.ipa_bits())
            || !is_valid_rtt_cmd(ipa, RTT_PAGE_LEVEL, rd.ipa_bits())
        {
            return Err(Error::RmiErrorInput);
        }

        let (pa, top) = crate::rtt::data_destroy(realm_id, ipa)?;

        // data granule lock and change state
        set_state_and_get_granule!(pa, GranuleState::Delegated)?;

        ret[1] = pa;
        ret[2] = top;
        Ok(())
    });

    // Map an unprotected IPA to a non-secure PA.
    listen!(mainloop, rmi::RTT_MAP_UNPROTECTED, |arg, _ret, _rmm| {
        let ipa = arg[1];
        let level = arg[2];
        let host_s2tte = arg[3];
        let s2tte = S2TTE::from(host_s2tte);
        if !s2tte.is_host_ns_valid(level) {
            return Err(Error::RmiErrorInput);
        }

        // rd granule lock
        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();

        if !is_valid_rtt_cmd(ipa, level, rd.ipa_bits()) {
            return Err(Error::RmiErrorInput);
        }
        crate::rtt::map_unprotected(rd, ipa, level, host_s2tte)?;
        Ok(())
    });

    // Unmap a non-secure PA at an unprotected IPA
    listen!(mainloop, rmi::RTT_UNMAP_UNPROTECTED, |arg, _ret, _rmm| {
        let ipa = arg[1];

        let rd_granule = get_granule_if!(arg[0], GranuleState::RD)?;
        let rd = rd_granule.content::<Rd>();
        let realm_id = rd.id();

        let level = arg[2];
        if (level < RTT_MIN_BLOCK_LEVEL)
            || (level > RTT_PAGE_LEVEL)
            || !is_valid_rtt_cmd(ipa, level, rd.ipa_bits())
        {
            return Err(Error::RmiErrorInput);
        }
        crate::rtt::unmap_unprotected(realm_id, ipa, level)?;
        Ok(())
    });
}

fn realm_ipa_size(ipa_bits: usize) -> usize {
    1 << ipa_bits
}

pub fn realm_par_size(ipa_bits: usize) -> usize {
    realm_ipa_size(ipa_bits) / 2
}

pub fn is_protected_ipa(ipa: usize, ipa_bits: usize) -> bool {
    ipa < realm_par_size(ipa_bits)
}

pub fn validate_ipa(ipa: usize, ipa_bits: usize) -> Result<(), Error> {
    if !is_granule_aligned(ipa) {
        error!("ipa: {:x} is not aligned with {:x}", ipa, GRANULE_SIZE);
        return Err(Error::RmiErrorInput);
    }

    if !is_protected_ipa(ipa, ipa_bits) {
        error!(
            "ipa: {:x} is not in protected ipa range {:x}",
            ipa,
            realm_par_size(ipa_bits)
        );
        return Err(Error::RmiErrorInput);
    }

    if !is_valid_rtt_cmd(ipa, RTT_PAGE_LEVEL, ipa_bits) {
        return Err(Error::RmiErrorInput);
    }

    Ok(())
}
