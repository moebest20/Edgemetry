declare module '*.mmdb' {
  const content: ArrayBuffer;
  export default content;
}

declare module 'maxminddb-wasm/browser/index_bg.wasm' {
  const wasm: WebAssembly.Module;
  export default wasm;
}
