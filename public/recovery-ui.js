import { wordlist } from "./bip39-english.js";
import { generateDemoKey, generateMnemonic } from "./bip39.mjs";

const generateButton = document.querySelector("#recovery-generate");
const regenerateButton = document.querySelector("#recovery-regenerate");
const copyButton = document.querySelector("#recovery-copy");
const result = document.querySelector("#recovery-result");
const words = document.querySelector("#recovery-words");
const status = document.querySelector("#recovery-status");
let currentPhrase = "";
const demoKeyButton = document.querySelector("#demo-key-generate");
const demoKeyResult = document.querySelector("#demo-key-result");
const demoKeyValue = document.querySelector("#demo-key-value");
const demoKeyStatus = document.querySelector("#demo-key-status");

async function generatePhrase() {
  generateButton.disabled = true;
  regenerateButton.disabled = true;
  status.textContent = "Generating securely…";

  try {
    currentPhrase = await generateMnemonic(wordlist);
    words.replaceChildren(...currentPhrase.split(" ").map((word) => {
      const item = document.createElement("li");
      item.textContent = word;
      return item;
    }));
    result.hidden = false;
    status.textContent = "Generated locally in this browser. This page does not send the phrase to the server.";
    copyButton.textContent = "Copy phrase";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not generate a recovery phrase.";
  } finally {
    generateButton.disabled = false;
    regenerateButton.disabled = false;
  }
}

generateButton.addEventListener("click", generatePhrase);
regenerateButton.addEventListener("click", generatePhrase);
copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(currentPhrase);
    status.textContent = "Phrase copied. Keep it private and secure.";
    copyButton.textContent = "Copied";
  } catch {
    status.textContent = "Clipboard access failed. Select and copy the displayed words manually.";
  }
});

demoKeyButton.addEventListener("click", () => {
  try {
    demoKeyValue.textContent = generateDemoKey();
    demoKeyResult.hidden = false;
    demoKeyStatus.textContent = "Demo string only — not an actual wallet private key.";
  } catch (error) {
    demoKeyStatus.textContent = error instanceof Error ? error.message : "Could not generate a demo string.";
    demoKeyResult.hidden = false;
  }
});
