//! Timer work shared by native engines and the Wasm host.

/// Common meaning of a timer request across native and Wasm engines.
///
/// The requested fields describe work before UMEM allocation. The host or
/// native frame registry fills in `allocated_frames` after allocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineTimerPlan {
    pub timeout_frames: u32,
    pub packet_frames: u32,
    pub allocated_frames: u32,
    pub route: u32,
}

impl EngineTimerPlan {
    pub const fn new(timeout_frames: u32, packet_frames: u32, route: u32) -> Self {
        Self {
            timeout_frames,
            packet_frames,
            allocated_frames: 0,
            route,
        }
    }

    #[inline]
    pub const fn requested_frames(self) -> u32 {
        self.timeout_frames.saturating_add(self.packet_frames)
    }

    #[inline]
    pub const fn with_allocated(self, allocated_frames: u32) -> Self {
        Self {
            allocated_frames,
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EngineTimerPlan;

    #[test]
    fn timer_plan_accounts_for_requests_and_allocation() {
        let plan = EngineTimerPlan::new(12, 20, 0);
        assert_eq!(plan.requested_frames(), 32);
        assert_eq!(plan.with_allocated(7).allocated_frames, 7);
        assert_eq!(plan.route, 0);
    }
}
