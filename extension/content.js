chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "ss_cookies") return;
  window.dispatchEvent(new CustomEvent("ss_ext_cookies", { detail: { cookies: msg.cookies, domain: msg.domain || "" } }));
});
