import * as wasm from "wasm-package";

function greetMe() {
  wasm.greet("What is your name?");
}

const button = document.getElementById("button");
button.addEventListener("click", greetMe);
