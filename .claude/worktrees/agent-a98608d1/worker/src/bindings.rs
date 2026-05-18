use wasmtime::component::*;

bindgen!({
    world: "automation-node",
    path: "../wit/talos.wit",
    imports: {
        default: async,
    },
    exports: {
        default: async,
    }
});
