const packetsDiv = document.getElementById('table');
const analysisDiv = document.getElementById('right');
const timelineDiv = document.getElementById('timeline');

let selectedPacket = null;
let packets = [];
let filterText = "";
// =========================
// SOCKET
// =========================
const socket = io("http://127.0.0.1:5000");
const filterInput = document.getElementById("filterInput");

filterInput.addEventListener("input", (e) => {
    filterText = e.target.value.toLowerCase();
    renderList();
});
socket.on("connect", () => {
    analysisDiv.innerText = "🟢 Conectado al sniffer...";
});

// =========================
// SAFE
// =========================
function safe(v) {
    if (!v) return "—";
    if (typeof v === "object") return v.value || v.meaning || JSON.stringify(v);
    return v;
}

// =========================
// PACKET IN
// =========================
socket.on("packet", (packet) => {

    packet._meta = {
        time: new Date().toLocaleTimeString()
    };

    packets.unshift(packet);

    if (packets.length > 100) packets.pop();

    renderList();
    addTimeline(packet);
});

// =========================
// LEFT LIST (PRO)
// =========================
function matchFilter(p) {

    if (!filterText) return true;

    const ip = p.ipv4;

    const layer2 = (p.type || "").toLowerCase();
    const layer4 = (ip?.header?.protocol?.meaning || "").toLowerCase();

    const src = (ip?.header?.source_ip?.value || "").toLowerCase();
    const dst = (ip?.header?.destination_ip?.value || "").toLowerCase();

    return (
        layer2.includes(filterText) ||
        layer4.includes(filterText) ||
        src.includes(filterText) ||
        dst.includes(filterText)
    );
}

function renderList() {

    packetsDiv.innerHTML = "";

    packets
        .filter(matchFilter)
        .forEach(p => {

            const div = document.createElement("div");
            div.className = "packet-item";

            const ip = p.ipv4;

            let layer2 = p.type || "UNKNOWN";
            let layer4 = ip?.header?.protocol?.meaning || "";

            const src = ip?.header?.source_ip?.value || "—";
            const dst = ip?.header?.destination_ip?.value || "—";

            div.innerHTML = `
                <b>${layer2}${layer4 ? " → " + layer4 : ""}</b><br>
                ${src} → ${dst}
            `;

            div.onclick = () => showPacket(p);

            packetsDiv.appendChild(div);
        });
}

// =========================
// PACKET INSPECTOR (WIRESHARK STYLE)
// =========================
function showPacket(p) {

    selectedPacket = p;

    const ip = p.ipv4;

    if (!ip) {
        analysisDiv.innerHTML = `
<h3>Non IPv4 Packet</h3>
<pre>${JSON.stringify(p, null, 2)}</pre>
`;
        return;
    }

    const h = ip.header || {};

    let transport = ip.transport
        ? Object.entries(ip.transport).map(([k,v]) => `
<b>${k.toUpperCase()}</b>
${JSON.stringify(v, null, 2)}
`).join("\n")
        : "No transport data";

    analysisDiv.innerHTML = `
<h3>📦 Packet Inspector</h3>

<h4>IPv4</h4>
<pre>
Source: ${safe(h.source_ip)}
Destination: ${safe(h.destination_ip)}
Protocol: ${safe(h.protocol)}
TTL: ${safe(h.ttl)}
Checksum: ${safe(h.checksum)}
</pre>

<h4>Transport</h4>
<pre>${transport}</pre>

<h4>Raw Payload</h4>
<pre>${p.payload_hex || "N/A"}</pre>
`;
}

// =========================
// TIMELINE SIMPLE
// =========================
socket.on("packet", (p) => {

    const div = document.createElement("div");
    div.style.minWidth = "160px";
    div.style.padding = "6px";
    div.style.background = "#222";
    div.style.fontSize = "11px";

    const ip = p.ipv4;

    div.innerHTML = `
        ${p.type}<br>
        ${ip?.header?.source_ip?.value || "?"} → ${ip?.header?.destination_ip?.value || "?"}
    `;

    timelineDiv.appendChild(div);
});