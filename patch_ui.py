import re

dashboard_file = 'd:/New folder/SE/KI2-NAM3/ATPM/demo/templates/dashboard.html'
with open(dashboard_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Add Mitigation Control Panel below Detection Panel
mitigation_panel = """      <div class="panel">
        <div class="panel-header">
          <h2>Mitigation Control</h2>
          <div class="badge" id="mitigationStatusChip">Status: ● INACTIVE</div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 15px;">
          <button class="filter-btn" style="background: var(--red); color: white; border: none; padding: 10px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 8px; justify-content: center;" onclick="activateMitigation('rate_limit')"><span>🚫</span> Block Flooding IPs</button>
          <button class="filter-btn" style="background: var(--amber); color: white; border: none; padding: 10px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 8px; justify-content: center;" onclick="activateMitigation('ue_throttle')"><span>⏱</span> Throttle UE Registration</button>
          <button class="filter-btn" style="background: #9333ea; color: white; border: none; padding: 10px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 8px; justify-content: center;" onclick="activateMitigation('slice_cap')"><span>🗂</span> Cap Slice Allocation</button>
          <button class="filter-btn" id="deactivateMitigationBtn" style="background: var(--muted); color: white; border: none; padding: 10px; border-radius: 8px; cursor: pointer; display: none; align-items: center; justify-content: center;" onclick="deactivateMitigation()">Deactivate Mitigation</button>
        </div>
        <div class="muted" style="margin-bottom: 8px; font-size: 13px; font-weight: 600;">Live Actions:</div>
        <div id="mitigationActions" style="background: var(--panel-alt); border-radius: 8px; padding: 10px; font-size: 13px; max-height: 150px; overflow-y: auto; display: flex; flex-direction: column; gap: 6px; border: 1px solid var(--border);">
        </div>
      </div>
"""
content = content.replace('      </div>\n    </div>\n\n    <div class="table-wrap">', '      </div>\n' + mitigation_panel + '\n    </div>\n\n    <div id="mitigation-banner" style="display: none; padding: 12px; margin-bottom: 18px; border-radius: 12px; font-weight: bold; text-align: center;"></div>\n    <div class="table-wrap">')

# Modify Javascript to support Mitigation
js_additions = """
    let mitigationState = { active: false, mode: null, blocked_ips: [], actions_log: [] };
    let borderInterval = null;

    async function activateMitigation(mode) {
      await fetch("/internal/mitigation/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode })
      });
    }

    async function deactivateMitigation() {
      await fetch("/internal/mitigation/deactivate", { method: "POST" });
    }

    function updateMitigationUI(state) {
      mitigationState = state;
      const chip = document.getElementById("mitigationStatusChip");
      const deactivateBtn = document.getElementById("deactivateMitigationBtn");
      const banner = document.getElementById("mitigation-banner");
      const actionsLog = document.getElementById("mitigationActions");

      if (state.active) {
        chip.textContent = "Status: ● " + state.mode.toUpperCase();
        chip.style.color = "var(--red)";
        deactivateBtn.style.display = "flex";
        banner.style.display = "block";
        
        if (state.mode === 'rate_limit') {
          banner.style.background = "#fef2f2";
          banner.style.color = "#991b1b";
          banner.style.border = "1px solid #fecaca";
          banner.textContent = `🚫 Rate Limiting Active — ${state.blocked_ips.length} IPs blocked`;
        } else if (state.mode === 'ue_throttle') {
          banner.style.background = "#fffbeb";
          banner.style.color = "#92400e";
          banner.style.border = "1px solid #fde68a";
          banner.textContent = `⏱ UE Registration Throttled — /ue-registration limited to 30 req/s`;
        } else if (state.mode === 'slice_cap') {
          banner.style.background = "#faf5ff";
          banner.style.color = "#6b21a8";
          banner.style.border = "1px solid #e9d5ff";
          banner.textContent = `🗂 Slice Cap Active — /slice/allocate capped at 20 req/s`;
        }
      } else {
        chip.textContent = "Status: ● INACTIVE";
        chip.style.color = "inherit";
        deactivateBtn.style.display = "none";
        banner.style.display = "none";
      }

      const currentActions = (state.actions_log || []).slice(-20).reverse();
      actionsLog.innerHTML = currentActions.map(a => {
        const timeStr = formatTime(a.time);
        return `<div style="padding: 4px; border-bottom: 1px solid var(--border);">${timeStr} ${a.action}</div>`;
      }).join("");
      
      updateChartHighlighting();
    }
    
    function updateChartHighlighting() {
      const mode = mitigationState.active ? mitigationState.mode : null;
      if (!borderInterval) {
        borderInterval = setInterval(() => {
          endpointChart.update("none");
        }, 500);
      }
      
      const widthPhase = Math.floor(Date.now() / 500) % 2 === 0 ? 8 : 4;
      const datasets = endpointChart.data.datasets[0];
      
      datasets.borderWidth = endpointChart.data.labels.map(l => {
        if (mode === 'rate_limit') return widthPhase;
        if (mode === 'ue_throttle' && l === '/ue-registration') return widthPhase;
        if (mode === 'slice_cap' && l === '/slice/allocate') return widthPhase;
        return 0;
      });
      datasets.borderColor = endpointChart.data.labels.map(l => {
        if (mode === 'rate_limit') return '#dc2626';
        if (mode === 'ue_throttle' && l === '/ue-registration') return '#d97706';
        if (mode === 'slice_cap' && l === '/slice/allocate') return '#9333ea';
        return '#ffffff';
      });
    }
"""

content = content.replace('    let currentFilter = "all";', '    let currentFilter = "all";\n' + js_additions)
content = content.replace('      updateCharts(data);\n    });', '      updateCharts(data);\n      if (data.mitigation_status) updateMitigationUI(data.mitigation_status);\n    });')

log_table_row = """
      const table = document.getElementById("logTable");
      table.innerHTML = rows.reverse().map((row) => {
        let blockedClass = row.blocked ? "blocked" : "";
        let borderStyle = "";
        let badgeText = row.blocked ? "Yes" : "No";
        let badgeColor = "";
        
        if (mitigationState.active) {
            if (mitigationState.mode === 'rate_limit' && mitigationState.blocked_ips.includes(row.ip)) {
                borderStyle = "border-left: 4px solid var(--red);";
                badgeText = "<span style='background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold;'>BLOCKED</span>";
            } else if (mitigationState.mode === 'ue_throttle' && row.endpoint === '/ue-registration') {
                borderStyle = "border-left: 4px solid var(--amber);";
                badgeText = "<span style='background: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold;'>THROTTLED</span>";
            } else if (mitigationState.mode === 'slice_cap' && row.endpoint === '/slice/allocate') {
                borderStyle = "border-left: 4px solid #9333ea;";
                badgeText = "<span style='background: #f3e8ff; color: #6b21a8; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold;'>QUEUED</span>";
            }
        }

        return `
          <tr class="${blockedClass}">
            <td style="${borderStyle}">${formatTime(row.timestamp)}</td>
            <td>${row.ip || "-"}</td>
            <td>${row.endpoint || "-"}</td>
            <td>${row.method || "-"}</td>
            <td>${row.status_code ?? "-"}</td>
            <td>${((row.response_time || 0) * 1000).toFixed(1)} ms</td>
            <td>${badgeText}</td>
          </tr>`;
      }).join("");
"""

content = content.replace("""      const table = document.getElementById("logTable");
      table.innerHTML = rows.reverse().map((row) => {
        const blockedClass = row.blocked ? "blocked" : "";
        return `
          <tr class="${blockedClass}">
            <td>${formatTime(row.timestamp)}</td>
            <td>${row.ip || "-"}</td>
            <td>${row.endpoint || "-"}</td>
            <td>${row.method || "-"}</td>
            <td>${row.status_code ?? "-"}</td>
            <td>${((row.response_time || 0) * 1000).toFixed(1)} ms</td>
            <td>${row.blocked ? "Yes" : "No"}</td>
          </tr>`;
      }).join("");""", log_table_row)

with open(dashboard_file, 'w', encoding='utf-8') as f:
    f.write(content)


attacker_file = 'd:/New folder/SE/KI2-NAM3/ATPM/demo/templates/attacker.html'
with open(attacker_file, 'r', encoding='utf-8') as f:
    att_content = f.read()

att_content = att_content.replace('<h3 class="attack-name">HTTP Flood</h3>\\n            <p class="attack-desc">Overwhelms SBA API endpoints (NRF/AMF) with massive HTTP requests</p>', '<h3 class="attack-name">HTTP Flood</h3>\\n            <p class="attack-desc">Overwhelms SBA API endpoints (NRF/AMF) with massive HTTP requests</p>\\n            <div style="margin-top: 8px; font-size: 12px; background: #f1f5f9; padding: 4px 8px; border-radius: 999px; display: inline-block; color: #64748b; font-weight: 600;">Counter with: Block Flooding IPs</div>')
att_content = att_content.replace('<h3 class="attack-name">Signaling Storm</h3>\\n            <p class="attack-desc">Simulates thousands of UEs simultaneously registering, exhausting AMF capacity</p>', '<h3 class="attack-name">Signaling Storm</h3>\\n            <p class="attack-desc">Simulates thousands of UEs simultaneously registering, exhausting AMF capacity</p>\\n            <div style="margin-top: 8px; font-size: 12px; background: #f1f5f9; padding: 4px 8px; border-radius: 999px; display: inline-block; color: #64748b; font-weight: 600;">Counter with: Throttle UE Registration</div>')
att_content = att_content.replace('<h3 class="attack-name">Slice Exhaustion</h3>\\n            <p class="attack-desc">Floods slice allocation endpoint, preventing legitimate slice provisioning</p>', '<h3 class="attack-name">Slice Exhaustion</h3>\\n            <p class="attack-desc">Floods slice allocation endpoint, preventing legitimate slice provisioning</p>\\n            <div style="margin-top: 8px; font-size: 12px; background: #f1f5f9; padding: 4px 8px; border-radius: 999px; display: inline-block; color: #64748b; font-weight: 600;">Counter with: Cap Slice Allocation</div>')

with open(attacker_file, 'w', encoding='utf-8') as f:
    f.write(att_content)
