/* Phase 7.2 substituted-DSO control.
 *
 * A harmless shared object with a distinct hash. `ci/bridge-gate.sh` loads it
 * into the pinned Gemel provider with LD_PRELOAD and captures the actual
 * loader map; the bridge must classify the closure as `substituted` and
 * refuse custody.
 */
__attribute__((visibility("default"))) int frf_bridge_substitute_marker(void) {
    return 42;
}
