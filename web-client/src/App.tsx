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
      console.log("benchmark start");
      const privateKey = await workerApi.sample_rsa_private_key(1024);
      let msg = new Uint8Array([0]);
      const publicKey = await workerApi.to_public_key(privateKey);
      const signature = await workerApi.sign(privateKey, msg);
      const start = performance.now();
      const proof = await workerApi.prove_1024_64(publicKey, msg, signature);
      console.log('proof generation', performance.now() - start);
      let isValid = await workerApi.verify_1024_64(proof);
      console.log(isValid)
      console.log("benchmark end");
    } catch (e) {
      console.error(e)
    }
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
