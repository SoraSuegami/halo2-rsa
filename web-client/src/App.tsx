import React, { useState, useEffect } from 'react';
import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';

function App() {
  const worker = new Worker(new URL('./rsa-worker', import.meta.url), {
    name: 'rsa-worker',
    type: 'module',
  });
  const workerApi = wrap<import('./rsa-worker').RSAWorker>(worker);
  const [ans, setAns] = useState(0);

  async function test() {
    try {
      const pk = await workerApi.fetch_pk();
      const vk = await workerApi.fetch_vk();
      console.log("benchmark start");
      const privateKey = await workerApi.sample_rsa_private_key(2048);
      let msg = new Uint8Array([0]);
      const publicKey = await workerApi.to_public_key(privateKey);
      const signature = await workerApi.sign(privateKey, msg);
      const start = performance.now();
      // const proof = await workerApi.prove_1024_64(pk, publicKey, msg, signature);
      // const proof = await workerApi.prove_1024_1024(pk, publicKey, msg, signature);
      const proof = await workerApi.prove_2048_64(pk, publicKey, msg, signature);
      console.log('proof generation', performance.now() - start);
      // let isValid = await workerApi.verify_1024_64(vk, proof);
      // let isValid = await workerApi.verify_1024_1024(vk, proof);
      let isValid = await workerApi.verify_2048_64(vk, proof);
      console.log(isValid)
      console.log("benchmark end");
    } catch (e) {
      console.log(e)
    }
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
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
    </div>
  );
}

export default App;
