import { expose } from 'comlink';
async function fetch_params() {
  const response = await fetch('http://localhost:3000/params.bin');
  const bytes = await response.arrayBuffer();
  const params = new Uint8Array(bytes);
  return params;
}

async function sample_rsa_private_key(): Promise<any> {
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);

  const private_key = multiThread.sample_rsa_private_key();
  return private_key
}

async function to_public_key(private_key: any): Promise<any> {
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);

  const public_key = multiThread.generate_rsa_public_key(private_key);
  return public_key
}

async function sign(private_key: any, msg: any): Promise<any> {
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);

  const sign = multiThread.sign(private_key, msg);
  return sign
}

async function sha256_msg(msg: any): Promise<any> {
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);

  const ret = multiThread.sha256_msg(msg);
  return ret
}

async function prove(
  public_key: any,
  msg: any,
  signature: any
): Promise<any> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.prove_pkcs1v15_1024_128_circuit(params, public_key, msg, signature);
  return ret;
}

async function verify(
  public_key: any,
  hashed_msg: any,
  proof: any
): Promise<boolean> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.verify_pkcs1v15_1024_128_circuit(params, public_key, hashed_msg, proof);
  return ret;
}

async function prove_no_sha2(
  public_key: any,
  hashed_msg: any,
  signature: any
): Promise<any> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.prove_pkcs1v15_1024_128_circuit_no_sha2(params, public_key, hashed_msg, signature);
  return ret;
}

async function verify_no_sha2(
  public_key: any,
  hashed_msg: any,
  proof: any
): Promise<boolean> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.verify_pkcs1v15_1024_128_circuit_no_sha2(params, public_key, hashed_msg, proof);
  return ret;
}

const exports = {
  sign,
  sample_rsa_private_key,
  to_public_key,
  sha256_msg,
  prove,
  verify,
  prove_no_sha2,
  verify_no_sha2
};
export type RSAWorker = typeof exports;

expose(exports);