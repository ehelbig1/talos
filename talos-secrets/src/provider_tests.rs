#[cfg(test)]
#[allow(clippy::module_inception, clippy::clone_on_copy)]
// `module_inception` — file-named-after-its-mod is conventional for our
// `*_tests.rs` companion files. `clone_on_copy` — the `slot_handle_clone`
// test deliberately exercises `.clone()` on a `Copy` type.
mod tests {
    use crate::SlotHandle;

    #[test]
    fn slot_handle_equality() {
        let handle1 = SlotHandle(42);
        let handle2 = SlotHandle(42);
        let handle3 = SlotHandle(43);

        assert_eq!(handle1, handle2);
        assert_ne!(handle1, handle3);
    }

    #[test]
    fn slot_handle_hash() {
        use std::collections::HashSet;

        let handle1 = SlotHandle(42);
        let handle2 = SlotHandle(42);
        let handle3 = SlotHandle(43);

        let mut set = HashSet::new();
        set.insert(handle1);
        set.insert(handle2);
        set.insert(handle3);

        // Only 2 unique values
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn slot_handle_copy() {
        let handle1 = SlotHandle(42);
        let handle2 = handle1;

        // handle1 should still be usable after copy
        assert_eq!(handle1.0, 42);
        assert_eq!(handle2.0, 42);
    }

    #[test]
    fn slot_handle_clone() {
        let handle1 = SlotHandle(42);
        let handle2 = handle1.clone();

        assert_eq!(handle1, handle2);
    }

    #[test]
    fn slot_handle_debug() {
        let handle = SlotHandle(42);
        let debug_str = format!("{:?}", handle);

        assert!(debug_str.contains("SlotHandle"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn slot_handle_from_u64() {
        let handle: SlotHandle = SlotHandle(12345);
        assert_eq!(handle.0, 12345);
    }

    #[test]
    fn slot_handle_zero() {
        let handle = SlotHandle(0);
        assert_eq!(handle.0, 0);
    }

    #[test]
    fn slot_handle_max_u64() {
        let handle = SlotHandle(u64::MAX);
        assert_eq!(handle.0, u64::MAX);
    }
}
