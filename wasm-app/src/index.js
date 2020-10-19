import * as wasm from "wasm-package";

function multiply(n1, n2) {
  let result = "Not all inputs are defined yet!";
  const resultLabel = document.getElementById("result");

  if (n1 && n1 !== undefined && n2 && n2 !== undefined) {
    result = wasm.multiply(n1, n2);

    if (result === 0) {
      result = "An overflow has occurred. The input values are too large.";
    }
  }

  resultLabel.innerHTML = result;
}

function onButtonClick() {
  const nr1 = document.getElementById("nr1").value;
  const nr2 = document.getElementById("nr2").value;
  multiply(nr1, nr2);
}

const button = document.getElementById("button");
button.addEventListener("click", onButtonClick);
