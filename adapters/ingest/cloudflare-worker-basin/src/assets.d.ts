declare module "*.wasm" {
  const wasmModule: WebAssembly.Module;
  export default wasmModule;
}

declare module "*.yar" {
  const ruleText: string;
  export default ruleText;
}
