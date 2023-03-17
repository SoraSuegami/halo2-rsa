import React, { useState, useEffect } from 'react';
import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';
import { mean, sampleVariance } from 'simple-statistics'
const Plotly = require('plotly.js-dist');

function App() {
  const worker = new Worker(new URL('./bench-worker', import.meta.url), {
    name: 'bench-worker',
    type: 'module',
  });
  const workerApi = wrap<import('./bench-worker').BenchWorker>(worker);
  const [ans, setAns] = useState(0);

  async function test() {
    // const params = await fetch_params();
    // const pk = await fetch_pk();
    // const vk = await fetch_vk();

    // const multiThread = await import(
    //   'halo2-rsa'
    // );
    // await multiThread.default();
    // await multiThread.initThreadPool(navigator.hardwareConcurrency);
    // console.log("benchmark start");
    // const privateKey = await multiThread.sample_rsa_private_key(1024);
    // let msg = new Uint8Array([0]);
    // const publicKey = await multiThread.generate_rsa_public_key(privateKey);
    // const signature = await multiThread.sign(privateKey, msg);
    // const times = 20;
    // const indexes = [];
    // const benches = [];
    // let sumTime = 0;
    // for (let i = 0; i < times; i++) {
    //   indexes.push(i);
    //   const start = performance.now();
    //   const proof = await multiThread.prove_pkcs1v15_1024_1024_circuit(params, pk, publicKey, msg, signature);
    //   const sub = performance.now() - start;
    //   console.log(`index: ${i}, bench: ${sub} ms`);
    //   benches.push(sub);
    //   // sumTime += sub;
    //   const isValid = await mul.verify_1024_1024(wasm, params, vk, proof);
    //   console.log(isValid)
    // }
    console.log("bench start");
    let msg = new Uint8Array(new Array(32).fill(0));
    console.log(msg);
    const results = await workerApi.initHandlers(2048, msg, 100);
    const graph = document.getElementById('graph');
    // const avg = await results.avg;
    // const sdv = await results.sdv;
    const indexes = await results.indexes;
    const benches = await results.benches;
    Plotly.newPlot(graph, [{
      x: indexes,
      y: benches,
    }], {
      margin: { t: 0 }
    });
    console.log(`proving time average: ${mean(benches)} ms.`);
    console.log(`proving time variance: ${sampleVariance(benches)} ms.`);
    // try {
    //   const params = await workerApi.fetch_params();
    //   const pk = await workerApi.fetch_pk();
    //   const vk = await workerApi.fetch_vk();
    //   const wasm = await workerApi.init_wasm();
    //   console.log("benchmark start");
    //   const privateKey = await workerApi.sample_rsa_private_key(wasm, 1024);
    //   let msg = new Uint8Array([0]);
    //   const publicKey = await workerApi.to_public_key(wasm, privateKey);
    //   const signature = await workerApi.sign(wasm, privateKey, msg);
    //   const times = 20;
    //   const indexes = [];
    //   const benches = [];
    //   // let sumTime = 0;
    //   // for (let i = 0; i < times; i++) {
    //   //   indexes.push(i);
    //   //   const start = performance.now();
    //   //   const proof = await workerApi.prove_1024_1024(wasm, params, pk, publicKey, msg, signature);
    //   //   const sub = performance.now() - start;
    //   //   console.log(`index: ${i}, bench: ${sub} ms`);
    //   //   benches.push(sub);
    //   //   // sumTime += sub;
    //   //   const isValid = await workerApi.verify_1024_1024(wasm, params, vk, proof);
    //   //   console.log(isValid)
    //   // }
    //   // const graph = document.getElementById('graph');
    //   // Plotly.newPlot(graph, [{
    //   //   x: indexes,
    //   //   y: benches,
    //   // }], {
    //   //   margin: { t: 0 }
    //   // });
    //   // console.log(`proving time average: ${mean(benches)} ms.`);
    //   // console.log(`proving time variance: ${sampleVariance(benches)} ms.`);
    // } catch (e) {
    //   console.log(e)
    // }
    // const proof = await workerApi.prove_play();
    // console.log('ending', performance.now() - start);
    // console.log('outside proof', proof);

    // const verification = await workerApi.verify_play(proof, diff_js);
    // console.log('verified', verification);
    // console.log('time', performance.now() - start);
  }


  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.tsx</code> and save to reload.
        </p>
        {ans}
        <button onClick={test}>test</button>
        <div id="graph"></div>
      </header>
    </div>
  );
}

export default App;
