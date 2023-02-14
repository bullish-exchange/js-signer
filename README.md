# NodeJS/Javascript message signing example

This repository provides an example of signing any arbitrary message with an R1 key and produce an Bullish compatible signature

## How to use

### Import the library

```js
const getSignature = require('js-signer').getSignature
```

```js
import { getSignature } from 'js-signer'
```

### Generate Signature

```js
// import public private keys
// for demo: keys are hardcoded here
const privateKeyString = 'PVT_R1_ENSnpAGb4NHNA2chipxHQMVnAZdEAfRzHmJFEuxFkWvCXC5CG'
const publicKeyString = 'PUB_R1_8CHJquaQWe4Pkhp1fBR9deP5wkqfjuWdfhaKYDxGKCo7gQwU9C'

// create a function to generate singature for payload
// this functions internally calls getSignature from library
const signMessage = async message => {
  // create singature from payload by using getSignature from library
  const signature = await getSignature(message, publicKeyString, privateKeyString)

  // use the signature to add in the header of the API communication
  return signature
}

async function useSignature() {
  console.time('Signature generate in: ')

  // retrieve signature for the message
  const signature = await signMessage({ message: 'A very secret message' })

  // for demo: print the signature
  console.log(signature)
  console.timeEnd('Signature generate in: ')
}

useSignature()
```

## Example for different frameworks

### NodeJs

- [Code / Playground Link 🔗](https://stackblitz.com/edit/node-js-signer?file=index.js)

### React

- [Demo Link 🔗](https://react-js-signer.stackblitz.io)
- [Code / Playground Link 🔗](https://stackblitz.com/edit/react-js-signer?file=Signer.tsx)

### Angular

- [Demo Link 🔗](https://angular-js-signer.stackblitz.io)
- [Code / Playground Link 🔗](https://stackblitz.com/edit/angular-js-signer?file=src/app/app.component.ts)

### Vue

- [Demo Link 🔗](https://vue-js-signer.stackblitz.io)
- [Code / Playground Link 🔗](https://stackblitz.com/edit/vue-js-signer?file=src/App.vue)
