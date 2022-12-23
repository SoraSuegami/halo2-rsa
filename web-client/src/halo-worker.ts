import { expose } from 'comlink';
async function fetch_params() {
    const response = await fetch('http://localhost:3000/params.bin');
    const bytes = await response.arrayBuffer();
    const params = new Uint8Array(bytes);
    return params;
}

async function prove(

) {
    const params = await fetch_params();
    console.log("param length", params.length);
    console.log("params", params);

    console.log('genning proof');
    const multiThread = await import(
        'halo2-rsa'
      );
    await multiThread.default();
    await multiThread.initThreadPool(navigator.hardwareConcurrency);
    console.log('here we go');
    const g= new Uint8Array(100);
    const ret = multiThread.prove(params, g, g, g );
    return ret;
}

async function gen_key() { 
    const multiThread = await import(
        'halo2-rsa'
      );
    await multiThread.default();
    await multiThread.initThreadPool(navigator.hardwareConcurrency);

    const pk = multiThread.sample_rsa_key();
    return pk
}

async function to_public_key(pk:any) {
    const multiThread = await import(
        'halo2-rsa'
      );
    await multiThread.default();
    await multiThread.initThreadPool(navigator.hardwareConcurrency);

    const pub_key = multiThread.public_key(pk);
    return pub_key
}

async function sign(msg: any, pk: any) {
    const multiThread = await import(
        'halo2-rsa'
      );
    await multiThread.default();
    await multiThread.initThreadPool(navigator.hardwareConcurrency);

    const sign = multiThread.sign(pk, msg);
    return sign
}


const exports = {
    prove,
    sign,
    gen_key,
    to_public_key
};
export type HaloWorker = typeof exports;

expose(exports);