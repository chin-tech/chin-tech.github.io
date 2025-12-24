  function copyText(text) {
    // Best modern way (requires secure context: https or localhost)
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }

    // Fallback (works on http, older browsers)
    return new Promise((resolve, reject) => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "-9999px";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        ta.setSelectionRange(0, ta.value.length);
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error("execCommand failed"));
      } catch (e) {
        reject(e);
      }
    });
  }

  function addCopyButtons() {
    document.querySelectorAll("pre").forEach((pre) => {
      if (pre.parentElement?.classList?.contains("codewrap")) return;

      const code = pre.querySelector("code");
      if (!code) return;

      // Wrap <pre> so we can add a header bar above it
      const wrap = document.createElement("div");
      wrap.className =
        "codewrap my-6 rounded-xl border border-base-300 bg-base-200/40 overflow-hidden";

      const bar = document.createElement("div");
      bar.className =
        "codebar flex items-center justify-between px-3 py-2 bg-base-200/70 border-b border-base-300";

      const left = document.createElement("div");
      left.className = "flex items-center gap-2 opacity-70 text-xs font-mono";
      left.innerHTML = `<span class="w-2 h-2 rounded-full bg-error"></span>
                        <span class="w-2 h-2 rounded-full bg-warning"></span>
                        <span class="w-2 h-2 rounded-full bg-success"></span>`;

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-xs btn-ghost";
      btn.textContent = "Copy";

      btn.addEventListener("click", async () => {
        // Use textContent for raw code (safer than innerText)
        const text = code.textContent ?? "";
        try {
          await copyText(text);
          btn.textContent = "Copied!";
          btn.classList.add("btn-success");
          setTimeout(() => {
            btn.textContent = "Copy";
            btn.classList.remove("btn-success");
          }, 1200);
        } catch (e) {
          btn.textContent = "Failed";
          setTimeout(() => (btn.textContent = "Copy"), 1200);
          console.error("Copy failed:", e);
        }
      });

      bar.appendChild(left);
      bar.appendChild(btn);

      // Replace pre with wrap(bar + pre)
      pre.replaceWith(wrap);
      wrap.appendChild(bar);
      wrap.appendChild(pre);

      // Make sure the <pre> itself doesn't have weird margins
      pre.style.margin = "0";
      pre.style.borderRadius = "0";
    });
  }

  document.addEventListener("DOMContentLoaded", addCopyButtons);
  document.addEventListener("astro:page-load", addCopyButtons);
