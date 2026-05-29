(function () {
  "use strict";

  // ── DOM refs ──────────────────────────────────────────────────────────────
  // Declared first so showStatus() can be safely called by the config guard below.
  const questionEl = document.getElementById("question");
  const voteGrid   = document.getElementById("vote-grid");
  const statusEl   = document.getElementById("status");
  const resultsEl  = document.getElementById("results");
  const chartEl    = document.getElementById("chart");
  const totalEl    = document.getElementById("total");

  const cfg = window.VOTE_CONFIG;
  if (!cfg || !cfg.apiUrl || cfg.apiUrl === "https://YOUR_API_GATEWAY_URL") {
    showStatus("Configuration error: set window.VOTE_CONFIG.apiUrl before deploying.");
    return;
  }

  const POLL_ID      = cfg.pollId;
  const VOTED_KEY    = "voted_" + POLL_ID;
  const VOTER_ID_KEY = "voter_id";

  // ── Populate question + button labels ────────────────────────────────────
  questionEl.textContent = cfg.question;
  ["A", "B", "C", "D"].forEach(function (opt) {
    document.getElementById("btn-" + opt).textContent = cfg.options[opt];
  });

  // ── Voter identity (client-side, anonymous UUID) ──────────────────────────
  // The UUID is generated once, persisted in localStorage, and HMAC'd server-side.
  // No IP address is ever transmitted or stored.
  function getOrCreateVoterId() {
    var id = localStorage.getItem(VOTER_ID_KEY);
    if (!id) {
      id = generateUUID();
      localStorage.setItem(VOTER_ID_KEY, id);
    }
    return id;
  }

  // RFC 4122 v4 UUID — crypto.randomUUID where available, manual fallback.
  function generateUUID() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  // ── Boot ─────────────────────────────────────────────────────────────────
  var voterId = getOrCreateVoterId();

  if (localStorage.getItem(VOTED_KEY)) {
    // Already voted in this browser — skip buttons, fetch live results.
    hideVoteGrid();
    showStatus("You’ve already voted. Here are the live results:");
    fetchAndRenderResults();
  } else {
    attachVoteListeners(voterId);
  }

  // ── Vote button listeners ─────────────────────────────────────────────────
  function attachVoteListeners(vid) {
    voteGrid.addEventListener("click", function (e) {
      var btn = e.target.closest(".vote-btn");
      if (!btn) return;

      disableButtons();
      showStatus("Submitting…");

      var option = btn.getAttribute("data-option");
      submitVote(vid, option);
    });
  }

  function submitVote(vid, option) {
    fetch(cfg.apiUrl + "/vote", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ poll_id: POLL_ID, option: option, voter_id: vid }),
    })
      .then(function (res) { return res.json().then(function (data) { return { status: res.status, data: data }; }); })
      .then(function (r) {
        if (r.status === 200) {
          localStorage.setItem(VOTED_KEY, "1");
          hideVoteGrid();
          showStatus("Vote recorded! Here are the live results:");
          fetchAndRenderResults();
        } else if (r.status === 409) {
          // Server-side dedup caught a replay — mark locally and show results.
          localStorage.setItem(VOTED_KEY, "1");
          hideVoteGrid();
          showStatus("You’ve already voted. Here are the live results:");
          fetchAndRenderResults();
        } else {
          showStatus("Something went wrong. Please try again.");
          enableButtons();
        }
      })
      .catch(function () {
        showStatus("Network error. Please check your connection and try again.");
        enableButtons();
      });
  }

  // ── Results fetching + rendering ──────────────────────────────────────────
  function fetchAndRenderResults() {
    fetch(cfg.apiUrl + "/results?poll_id=" + encodeURIComponent(POLL_ID))
      .then(function (res) { return res.json(); })
      .then(function (data) { renderResults(data); })
      .catch(function () { showStatus("Could not load results. Please refresh."); });
  }

  function renderResults(data) {
    var opts  = data.options || {};
    var total = data.total   || 0;
    var order = ["A", "B", "C", "D"];

    chartEl.innerHTML = "";

    order.forEach(function (key) {
      var count = opts[key] || 0;
      var pct   = total > 0 ? Math.round((count / total) * 100) : 0;
      var label = cfg.options[key] || key;

      var row = document.createElement("div");
      row.className = "bar-row";

      var lbl = document.createElement("span");
      lbl.className   = "bar-label";
      lbl.textContent = label;

      var track = document.createElement("div");
      track.className = "bar-track";

      var fill = document.createElement("div");
      fill.className = "bar-fill opt-" + key;
      fill.style.width = pct + "%";

      var pctEl = document.createElement("span");
      pctEl.className   = "bar-pct";
      pctEl.textContent = pct + "%";

      track.appendChild(fill);
      row.appendChild(lbl);
      row.appendChild(track);
      row.appendChild(pctEl);
      chartEl.appendChild(row);
    });

    totalEl.textContent = total === 1 ? "1 vote total" : total + " votes total";
    resultsEl.hidden = false;
  }

  // ── UI helpers ────────────────────────────────────────────────────────────
  function hideVoteGrid()  { voteGrid.hidden = true; }
  function disableButtons() { voteGrid.querySelectorAll(".vote-btn").forEach(function (b) { b.disabled = true; }); }
  function enableButtons()  { voteGrid.querySelectorAll(".vote-btn").forEach(function (b) { b.disabled = false; }); }

  function showStatus(msg) {
    statusEl.textContent = msg;
    statusEl.hidden = false;
  }
})();
