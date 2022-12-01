# NodeJS/Javascript library for Signing Messages

This repository provides library to sign any arbitrary message with an EOSIO R1 key and produce an EOSIO signature

## How to use in NodeJs

### Online links for NodeJs

- [Code / Playground Link 🔗](https://stackblitz.com/edit/node-js-signer?file=index.js)

```js
// run `node index.js` in the terminal

// import the library
const getSignature = require('js-signer').getSignature

// import public private keys
// for demo: keys are hardcoded here
const privateKeyString = 'PVT_R1_ENSnpAGb4NHNA2chipxHQMVnAZdEAfRzHmJFEuxFkWvCXC5CG'
const publicKeyString = 'PUB_R1_8CHJquaQWe4Pkhp1fBR9deP5wkqfjuWdfhaKYDxGKCo7gQwU9C'

// create a function to generate singature for payload
// this functions internally calls getSignature from library
const signMessage = async message => await getSignature(message, publicKeyString, privateKeyString)

// call the function with payload to generate signature
const sigature = signMessage({ message: 'A very secret message' })

// use the signature to add in the header of the API communication
// for demo: print the signature
console.log(signature)
```

## How to use in react

### Online links for React

- [Demo Link 🔗](https://react-ts-9q3wkh.stackblitz.io)
- [Code / Playground Link 🔗](https://stackblitz.com/edit/react-ts-9q3wkh?file=App.tsx)

```js
// import the library
import { getSignature } from 'js-signer'

// import public private keys
// for demo: keys are hardcoded here
const privateKeyString = 'PVT_R1_27VszLEcLtvmkNJWT1DCvHRdaGsFSkXxYjqFpAdipzSbfVtJg3'
const publicKeyString = 'PUB_R1_73GKfPPwq8k7WeJFaTd2JhgfZx6U1tQACfohRQUp57wgEPz3KB'

export default function App() {
  const [signature, setSignature] = React.useState('')
  const [message, setMessage] = React.useState('')

  const signMessage = async message => {
    // create singature from payload by using getSignature from library
    const signature = await getSignature(message, publicKeyString, privateKeyString)

    // use the signature to add in the header of the API communication
    // for Demo: set signature to state to show in UI
    setSignature(signature)
  }

  const handleMessageUpdate = useCallback(value => {
    setMessage(value)
    signMessage(value)
  }, [])

  return (
    <main className="container">
      <h1>JS Signer</h1>
      <section className="input-group">
        <input
          className="form-control"
          type="text"
          name="secret-message"
          id="secret-message"
          placeholder="Secret Message"
          onChange={e => handleMessageUpdate(e.target.value)}
          value={message}
        />
        <label htmlFor="secret-message">Secret Message</label>
        <div className="req-mark">!</div>
      </section>
      <section className="card">
        <pre>{message ? signature : ''} </pre>
      </section>
      <footer>Write a message to create signature!</footer>
    </main>
  )
}
```

### Online links for Angular

- [Demo Link 🔗](https://angular-js-signer.stackblitz.io)
- [Code / Playground Link 🔗](https://stackblitz.com/edit/angular-js-signer?file=src/app/app.component.ts)

```html
<main class="container">
  <h1>JS Signer</h1>
  <section class="input-group">
    <input
      class="form-control"
      type="text"
      name="secret-message"
      id="secret-message"
      placeholder="Secret Message"
      [(ngModel)]="message"
      (keyup)="handleChange($event)"
    />
    <label for="secret-message">Secret Message</label>
    <div class="req-mark">!</div>
  </section>
  <section class="card">
    <pre *ngIf="signature">{{ signature }} </pre>
    <span *ngIf="!signature">Write a message to create signature!</span>
  </section>
</main>
```

```js
// import the library
import { Component } from '@angular/core';
import { getSignature } from 'js-signer';

// import public private keys
// for demo: keys are hardcoded here
const privateKeyString = 'PVT_R1_27VszLEcLtvmkNJWT1DCvHRdaGsFSkXxYjqFpAdipzSbfVtJg3'
const publicKeyString = 'PUB_R1_73GKfPPwq8k7WeJFaTd2JhgfZx6U1tQACfohRQUp57wgEPz3KB'

@Component({
  selector: 'my-app',
  templateUrl: './app.component.html',
  styleUrls: [ './app.component.css' ]
})
export class AppComponent  {
  public message = ''
  public signature = ''
  public handleChange = async ($event) => {
    const value = $event.target.value
    this.signature = await getSignature(value, publicKeyString, privateKeyString)
  }
}
```

### Online links for Vue

- [Demo Link 🔗](https://vue-m1tqpq.stackblitz.io)
- [Code / Playground Link 🔗](https://stackblitz.com/edit/vue-m1tqpq?file=src/components/Signature.vue)

```js
<template>
  <main class="container">
    <h1>JS Signer</h1>
    <section class="input-group">
      <input class="form-control" type="text" name="secret-message" id="secret-message" placeholder="Secret Message" @keyup="handleChange" />
      <label for="secret-message">Secret Message</label>
      <div class="req-mark">!</div>
    </section>
    <section class="card">
      <pre v-if="signature">{{ signature }} </pre>
      <span v-if="!signature">Write a message to create signature!</span>
    </section>
  </main>
</template>

<script>
  import { getSignature } from 'js-signer/dist/index.js'
  export default {
    data() {
      return { signature: '' }
    },
    methods: {
      async handleChange(event) {
        // import public private keys
        // for demo: keys are hardcoded here
        const privateKeyString = 'PVT_R1_27VszLEcLtvmkNJWT1DCvHRdaGsFSkXxYjqFpAdipzSbfVtJg3'
        const publicKeyString = 'PUB_R1_73GKfPPwq8k7WeJFaTd2JhgfZx6U1tQACfohRQUp57wgEPz3KB'

        const value = event.target.value;
        const signature = await getSignature(value, publicKeyString, privateKeyString)
        this.signature = signature
      }
    }
  }
</script>
```
