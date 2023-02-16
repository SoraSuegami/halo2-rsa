import { expose } from 'comlink';
async function fetch_params() {
  const response = await fetch('http://localhost:3000/params.bin');
  const bytes = await response.arrayBuffer();
  const params = new Uint8Array(bytes);
  return params;
}

async function fetch_pk() {
  const response = await fetch('http://localhost:3000/bench.pk');
  const bytes = await response.arrayBuffer();
  const pk = new Uint8Array(bytes);
  return pk;
}

async function fetch_vk() {
  const response = await fetch('http://localhost:3000/bench.vk');
  const bytes = await response.arrayBuffer();
  const vk = new Uint8Array(bytes);
  return vk;
}

async function sample_rsa_private_key(bits_len: number): Promise<any> {
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);

  const private_key = multiThread.sample_rsa_private_key(bits_len);
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

async function prove_1024_64(
  pk: any,
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
  const ret = multiThread.prove_pkcs1v15_1024_64_circuit(params, pk, public_key, msg, signature);
  return ret;
}

async function verify_1024_64(
  vk: any,
  proof: any
): Promise<boolean> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.verify_pkcs1v15_1024_64_circuit(params, vk, proof);
  return ret;
}


async function prove_1024_1024(
  pk: any,
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
  const ret = multiThread.prove_pkcs1v15_1024_1024_circuit(params, pk, public_key, msg, signature);
  return ret;
}

async function verify_1024_1024(
  vk: any,
  proof: any
): Promise<boolean> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.verify_pkcs1v15_1024_1024_circuit(params, vk, proof);
  return ret;
}

async function prove_2048_64(
  pk: any,
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
  const ret = multiThread.prove_pkcs1v15_2048_64_circuit(params, pk, public_key, msg, signature);
  return ret;
}

async function verify_2048_64(
  vk: any,
  proof: any
): Promise<boolean> {
  const params = await fetch_params();
  const multiThread = await import(
    'halo2-rsa'
  );
  await multiThread.default();
  await multiThread.initThreadPool(navigator.hardwareConcurrency);
  const ret = multiThread.verify_pkcs1v15_2048_64_circuit(params, vk, proof);
  return ret;
}


const exports = {
  fetch_params,
  fetch_pk,
  fetch_vk,
  sign,
  sample_rsa_private_key,
  to_public_key,
  sha256_msg,
  prove_1024_64,
  verify_1024_64,
  prove_1024_1024,
  verify_1024_1024,
  prove_2048_64,
  verify_2048_64,
};
export type RSAWorker = typeof exports;

expose(exports);