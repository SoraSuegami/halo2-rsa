import React, { useState, useEffect } from 'react';
import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';

function App() {
  const worker = new Worker(new URL('./halo-worker', import.meta.url), {
    name: 'halo-worker',
    type: 'module',
  });
  const workerApi = wrap<import('./halo-worker').HaloWorker>(worker);
  const [ans, setAns] = useState(0);

  async function test() {
    try { 
      const start = performance.now();
      const pk = await workerApi.gen_key();
      const pub_key = await workerApi.to_public_key(pk);
      let msg = new Uint8Array([5,4]);
      const signature = await workerApi.sign(msg, pk);
      console.log(signature);


    // console.log('btw', performance.now() - start);
    } catch(e) { 
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
