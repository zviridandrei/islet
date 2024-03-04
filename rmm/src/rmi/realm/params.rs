use crate::const_assert_eq;
use crate::granule::{GRANULE_SHIFT, GRANULE_SIZE};
use crate::host::Accessor as HostAccessor;
use crate::measurement::Hashable;
use crate::rmi::features;
use crate::rmi::rtt::{RTT_PAGE_LEVEL, S2TTE_STRIDE};
use crate::rmi::{HASH_ALGO_SHA256, HASH_ALGO_SHA512};
use armv9a::{define_bitfield, define_bits, define_mask};

const PADDING: [usize; 3] = [975, 960, 2020];

define_bits!(
    RmiRealmFlags,
    Lpa2[0 - 0],
    Sve[1 - 1],
    Pmu[2 - 2],
    Reserved[63 - 3]
);

#[repr(C)]
pub struct Params {
    pub flags: u64,
    pub s2sz: u8,
    padding0: [u8; 7],
    pub sve_v1: u8,
    padding1: [u8; 7],
    pub num_bps: u8,
    padding2: [u8; 7],
    pub num_wps: u8,
    padding3: [u8; 7],
    pub pmu_num_ctrs: u8,
    padding4: [u8; 7],
    pub hash_algo: u8,
    padding5: [u8; PADDING[0]],
    pub rpv: [u8; 64],
    padding6: [u8; PADDING[1]],
    pub vmid: u16,
    padding7: [u8; 6],
    pub rtt_base: u64,
    pub rtt_level_start: i64,
    pub rtt_num_start: u32,
    padding8: [u8; PADDING[2]],
}

const_assert_eq!(core::mem::size_of::<Params>(), GRANULE_SIZE);

impl Default for Params {
    fn default() -> Self {
        Self {
            flags: 0,
            s2sz: 0,
            sve_v1: 0,
            num_bps: 0,
            num_wps: 0,
            pmu_num_ctrs: 0,
            hash_algo: 0,
            rpv: [0; 64],
            vmid: 0,
            rtt_base: 0,
            rtt_level_start: 0,
            rtt_num_start: 0,
            padding0: [0; 7],
            padding1: [0; 7],
            padding2: [0; 7],
            padding3: [0; 7],
            padding4: [0; 7],
            padding5: [0; PADDING[0]],
            padding6: [0; PADDING[1]],
            padding7: [0; 6],
            padding8: [0; PADDING[2]],
        }
    }
}

impl core::fmt::Debug for Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Params")
            .field(
                "flags",
                &format_args!(
                    "lpa2: {:?} sve: {:?} pmu: {:?}",
                    RmiRealmFlags::new(self.flags).get_masked_value(RmiRealmFlags::Lpa2),
                    RmiRealmFlags::new(self.flags).get_masked_value(RmiRealmFlags::Sve),
                    RmiRealmFlags::new(self.flags).get_masked_value(RmiRealmFlags::Pmu)
                ),
            )
            .field("s2sz", &self.s2sz)
            .field("sve_v1", &self.sve_v1)
            .field("num_bps", &self.num_bps)
            .field("num_wps", &self.num_wps)
            .field("pmu_num_ctrs", &self.pmu_num_ctrs)
            .field("hash_algo", &self.hash_algo)
            .field("rpv", &self.rpv)
            .field("vmid", &self.vmid)
            .field("rtt_base", &format_args!("{:#X}", &self.rtt_base))
            .field("rtt_level_start", &self.rtt_level_start)
            .field("rtt_num_start", &self.rtt_num_start)
            .finish()
    }
}

impl Hashable for Params {
    fn hash(
        &self,
        hasher: &crate::measurement::Hasher,
        out: &mut [u8],
    ) -> Result<(), crate::measurement::MeasurementError> {
        hasher.hash_fields_into(out, |alg| {
            alg.hash_u64(0); // features aren't used
            alg.hash_u8(self.s2sz);
            alg.hash(self.padding0);
            alg.hash_u8(self.sve_v1);
            alg.hash(self.padding1);
            alg.hash_u8(self.num_bps);
            alg.hash(self.padding2);
            alg.hash_u8(self.num_wps);
            alg.hash(self.padding3);
            alg.hash_u8(self.pmu_num_ctrs);
            alg.hash(self.padding4);
            alg.hash_u8(self.hash_algo);
            alg.hash(self.padding5);
            alg.hash([0u8; 64]); // rpv is not used
            alg.hash(self.padding6);
            alg.hash_u16(0); // vmid is not used
            alg.hash(self.padding7);
            alg.hash_u64(0); // rtt_base is not used
            alg.hash_u64(0); // rtt_level_start is not used
            alg.hash_u32(0); // rtt_num_start is not used
            alg.hash(self.padding8);
        })
    }
}

impl HostAccessor for Params {
    fn validate(&self) -> bool {
        trace!("{:?}", self);
        if !features::validate(self.s2sz as usize) {
            return false;
        }

        // Check misconfigurations between IPA size and SL
        let ipa_bits = self.ipa_bits();
        let rtt_slvl = self.rtt_level_start as usize;

        let level = RTT_PAGE_LEVEL - rtt_slvl;
        let min_ipa_bits = level * S2TTE_STRIDE + GRANULE_SHIFT + 1;
        let max_ipa_bits = min_ipa_bits + (S2TTE_STRIDE - 1) + 4;
        let sl_ipa_bits = (level * S2TTE_STRIDE) + GRANULE_SHIFT + S2TTE_STRIDE;

        if (ipa_bits < min_ipa_bits) || (ipa_bits > max_ipa_bits) {
            return false;
        }

        let s2_num_root_rtts = {
            if sl_ipa_bits >= ipa_bits {
                1
            } else {
                1 << (ipa_bits - sl_ipa_bits)
            }
        };
        if s2_num_root_rtts != self.rtt_num_start {
            return false;
        }

        // TODO: We don't support pmu, sve, lpa2
        let flags = RmiRealmFlags::new(self.flags);
        if flags.get_masked_value(RmiRealmFlags::Lpa2) != 0 {
            return false;
        }
        if flags.get_masked_value(RmiRealmFlags::Sve) != 0 {
            return false;
        }
        if flags.get_masked_value(RmiRealmFlags::Pmu) != 0 {
            return false;
        }

        match self.hash_algo {
            HASH_ALGO_SHA256 | HASH_ALGO_SHA512 => true,
            _ => false,
        }
    }
}

impl Params {
    pub fn ipa_bits(&self) -> usize {
        features::ipa_bits(self.s2sz as usize)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::offset_of;

    #[test]
    fn spec_params() {
        assert_eq!(core::mem::size_of::<Params>(), GRANULE_SIZE);

        assert_eq!(offset_of!(Params, features_0), 0x0);
        assert_eq!(offset_of!(Params, s2sz), 0x8);
        assert_eq!(offset_of!(Params, sve_v1), 0x10);
        assert_eq!(offset_of!(Params, num_bps), 0x18);
        assert_eq!(offset_of!(Params, num_wps), 0x20);
        assert_eq!(offset_of!(Params, pmu_num_ctrs), 0x28);
        assert_eq!(offset_of!(Params, hash_algo), 0x30);
        assert_eq!(offset_of!(Params, rpv), 0x400);
        assert_eq!(offset_of!(Params, vmid), 0x800);
        assert_eq!(offset_of!(Params, rtt_base), 0x808);
        assert_eq!(offset_of!(Params, rtt_level_start), 0x810);
        assert_eq!(offset_of!(Params, rtt_num_start), 0x818);
    }
}
