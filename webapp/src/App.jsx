import { useState, useEffect } from "react";
import { apiFetch, PA_LIST } from "./api";
import { PA01, PA02, PA03, PA04, PA05, PA06 } from "./pages/PA01_06";
import { PA07, PA08, PA09, PA10, PA11, PA12 } from "./pages/PA07_12";
import { PA13, PA14, PA15, PA16, PA17, PA18, PA19, PA20 } from "./pages/PA13_20";
import "./index.css";

const PAGES = { pa01: PA01, pa02: PA02, pa03: PA03, pa04: PA04, pa05: PA05, pa06: PA06,
  pa07: PA07, pa08: PA08, pa09: PA09, pa10: PA10, pa11: PA11, pa12: PA12,
  pa13: PA13, pa14: PA14, pa15: PA15, pa16: PA16, pa17: PA17, pa18: PA18, pa19: PA19, pa20: PA20 };

export default function App() {
  const [activePa, setActivePa] = useState("pa01");
  const [apiStatus, setApiStatus] = useState("checking");

  useEffect(() => {
    apiFetch("/health").then(r => setApiStatus(r?.status === "healthy" ? "connected" : "offline"))
      .catch(() => setApiStatus("offline"));
  }, []);

  const ActivePage = PAGES[activePa];
  const groups = [...new Set(PA_LIST.map(p => p.group))];

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="sidebar-header">
          <h1>CS8.401</h1>
          <p>Cryptographic Primitives</p>
        </div>
        <div className={`api-badge ${apiStatus}`}>
          API: {apiStatus === "connected" ? "● Connected" : apiStatus === "checking" ? "◌ Checking..." : "○ Offline"}
        </div>
        <div className="sidebar-nav">
          {groups.map(group => (
            <div key={group}>
              <div className="nav-group-label">{group}</div>
              {PA_LIST.filter(p => p.group === group).map(pa => (
                <button key={pa.id} className={`nav-item ${activePa === pa.id ? 'active' : ''}`}
                  onClick={() => setActivePa(pa.id)}>
                  <span className="pa-num">{pa.num}</span>
                  <span>{pa.icon} {pa.name}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </nav>
      <main className="main-content">
        <ActivePage />
      </main>
    </div>
  );
}
