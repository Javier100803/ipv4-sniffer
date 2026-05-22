

const packetsDiv =
    document.getElementById('packets')

const analysisDiv =
    document.getElementById('analysis')

let selectedPacketElement = null

let openedField = null
const MAX_PACKETS = 50
const FIELD_RENDERERS = {

    version_ihl:
        renderVersionIhl,

    dscp_ecn:
        renderDscp,

    flags_fragment:
        renderFlags,

    total_length:
        (field) =>
            renderSimpleField(
                'TOTAL LENGTH',
                field
            ),

    identification:
        (field) =>
            renderSimpleField(
                'IDENTIFICATION',
                field
            ),

    ttl:
        (field) =>
            renderSimpleField(
                'TTL',
                field
            ),

    protocol:
        (field) =>
            renderSimpleField(
                'PROTOCOL',
                field
            ),

    checksum:
        (field) =>
            renderSimpleField(
                'CHECKSUM',
                field
            ),

    source_ip:
        (field) =>
            renderSimpleField(
                'SOURCE IP',
                field
            ),

    destination_ip:
        (field) =>
            renderSimpleField(
                'DESTINATION IP',
                field
            )
}

/* ========================================================= */
/* FETCH PACKETS */
/* ========================================================= */

async function fetchPacket() {

    try {

        const response =
            await fetch(
                'http://localhost:5000/packet'
            )

        const packet =
            await response.json()

        addPacket(packet)

    } catch (error) {

        console.error(error)
    }
}


/* ========================================================= */
/* ADD PACKET */
/* ========================================================= */

function addPacket(packet) {

    const item =
        document.createElement('div')

    item.className =
        'packet-item'

    const protocol =
        packet.ipv4?.header?.protocol?.meaning
        || 'UNKNOWN'

    const source =
        packet.ipv4?.header?.source_ip?.value
        || 'Unknown'

    const destination =
        packet.ipv4?.header?.destination_ip?.value
        || 'Unknown'

    item.innerHTML = `

        <strong>${protocol}</strong>

        <br><br>

        ${source}

        <br>

        ↓

        <br>

        ${destination}
    `

    item.onclick = () => {

        if (selectedPacketElement) {

            selectedPacketElement
                .classList
                .remove('active')
        }

        item.classList.add('active')

        selectedPacketElement = item

        showAnalysis(packet)
        function renderTransportLayer(packet) {

    const transport =
        packet.ipv4.transport

    if (!transport)
        return

    if (transport.tcp) {

        createSectionTitle(
            'TCP HEADER'
        )

        const tcp =
            transport.tcp.header

        for (const key in tcp) {

            const field =
                tcp[key]

            if (
                key === 'flags'
            ) {

                analysisDiv.appendChild(
                    renderTcpFlags(field)
                )

                continue
            }

            analysisDiv.appendChild(

                renderSimpleField(

                    key
                        .replace('_', ' ')
                        .toUpperCase(),

                    field
                )
            )
        }
    }
}
    }

    packetsDiv.prepend(item)

    while (
        packetsDiv.children.length > MAX_PACKETS
    ) {

        packetsDiv.removeChild(
            packetsDiv.lastChild
        )
    }
}


/* ========================================================= */
/* SHOW ANALYSIS */
/* ========================================================= */
function showAnalysis(packet) {

    analysisDiv.innerHTML = ''

    openedField = null

    if (!packet.ipv4) {

        analysisDiv.innerHTML = `

            <h2>
                Unsupported Protocol
            </h2>
        `

        return
    }

    const ipv4 =
        packet.ipv4.header

    createSectionTitle('IPv4 HEADER')

    for (const key in ipv4) {

        const renderer =
            FIELD_RENDERERS[key]

        if (!renderer)
            continue

        const field =
            ipv4[key]

        analysisDiv.appendChild(
            renderer(field)
        )
    }

    renderTransportLayer(packet)

renderHexView(packet)

}


/* ========================================================= */
/* SECTION TITLE */
/* ========================================================= */

function createSectionTitle(title) {

    const section =
        document.createElement('div')

    section.className =
        'section-title'

    section.innerText =
        title

    analysisDiv.appendChild(section)
}


/* ========================================================= */
/* HEX VIEW */
/* ========================================================= */

function renderHexView(packet) {

    const title =
        document.createElement('div')

    title.className =
        'section-title'

    title.innerText =
        'RAW FRAME'

    analysisDiv.appendChild(title)

    const container =
        document.createElement('div')

    container.className =
        'hex-container'

    const bytes =
        packet.ipv4.raw_bytes

    for (let i = 0; i < bytes.length; i += 8) {

        const row =
            document.createElement('div')

        row.className =
            'hex-row'

        const offset =
            document.createElement('div')

        offset.className =
            'offset'

        offset.innerText =
            i.toString(16)
             .padStart(4, '0')

        row.appendChild(offset)

        for (
            let j = i;
            j < i + 8 && j < bytes.length;
            j++
        ) {

            const byte =
                document.createElement('div')

            byte.className =
                'hex-byte'

            byte.id =
                `byte-${j}`

            byte.innerText =
                bytes[j]

            row.appendChild(byte)
        }

        container.appendChild(row)
    }

    analysisDiv.appendChild(container)
}


/* ========================================================= */
/* HIGHLIGHT */
/* ========================================================= */

function highlightBytes(
    offset,
    length
) {

    document
        .querySelectorAll('.hex-byte')
        .forEach(el => {

            el.classList.remove('active')
        })

    for (
        let i = offset;
        i < offset + length;
        i++
    ) {

        const byte =
            document.getElementById(
                `byte-${i}`
            )

        if (byte) {

            byte.classList.add('active')
        }
    }
}


/* ========================================================= */
/* GENERIC FIELD */
/* ========================================================= */

function createExpandableField(
    title,
    field,
    content
) {

    const card =
        document.createElement('div')

    card.className =
        'field-card'

    const header =
        document.createElement('div')

    header.className =
        'field-header'

    header.innerHTML = `

        <div class="field-title">
            ${title}
        </div>

        <div class="field-binary">
            ${field.raw_binary}
        </div>
    `

    const details =
        document.createElement('div')

    details.className =
        'field-details'

    details.innerHTML =
        content

    header.onclick = () => {

        document
            .querySelectorAll('.field-details')
            .forEach(el => {

                el.style.display = 'none'
            })

        document
            .querySelectorAll('.field-card')
            .forEach(el => {

                el.classList.remove('active')
            })

        details.style.display = 'block'

        card.classList.add('active')

        highlightBytes(
            field.offset,
            field.length
        )
    }

    card.appendChild(header)

    card.appendChild(details)

    return card
}


/* ========================================================= */
/* VERSION + IHL */
/* ========================================================= */

function renderVersionIhl(field) {

    const version =
        field.breakdown.version

    const ihl =
        field.breakdown.ihl

    const content = `

        <div class="label">
            RAW HEX
        </div>

        <div class="value">
            ${field.raw_hex}
        </div>

        <div class="label">
            RAW BINARY
        </div>

        <div class="value">
            ${field.raw_binary}
        </div>

        <div class="breakdown">

            ${version.bits}
            ${ihl.bits}

        </div>

<pre>
│    └─ IHL
└────── Version
</pre>

        <div>

            <strong>Version:</strong>

            IPv${version.value}

        </div>

        <br>

        <div>

            <strong>IHL:</strong>

            ${ihl.meaning}

        </div>
    `

    return createExpandableField(
        'VERSION + IHL',
        field,
        content
    )
}


/* ========================================================= */
/* DSCP */
/* ========================================================= */

function renderDscp(field) {

    const dscp =
        field.breakdown.dscp

    const ecn =
        field.breakdown.ecn

    const content = `

        <div class="label">
            RAW HEX
        </div>

        <div class="value">
            ${field.raw_hex}
        </div>

        <div class="breakdown">

            ${dscp.bits}
            ${ecn.bits}

        </div>

<pre>
│      └─ ECN
└──────── DSCP
</pre>

        <div>

            <strong>Class:</strong>

            ${dscp.class}

        </div>

        <br>

        <div>

            <strong>Usage:</strong>

            ${dscp.usage}

        </div>
    `

    return createExpandableField(
        'DSCP + ECN',
        field,
        content
    )
}


/* ========================================================= */
/* FLAGS */
/* ========================================================= */

function renderFlags(field) {

    const flags =
        field.breakdown.flags

    const offset =
        field.breakdown.fragment_offset

    const content = `

        <div class="label">
            RAW HEX
        </div>

        <div class="value">
            ${field.raw_hex}
        </div>

        <div class="breakdown">

            ${flags.bits}
            ${offset.bits}

        </div>

<pre>
│││ └──────────── Fragment Offset
││└────────────── MF
│└─────────────── DF
└──────────────── Reserved
</pre>

        <div>

            <strong>DF:</strong>

            ${flags.df.meaning}

        </div>

        <br>

        <div>

            <strong>MF:</strong>

            ${flags.mf.meaning}

        </div>

        <br>

        <div>

            <strong>Offset:</strong>

            ${offset.value}

        </div>
    `

    return createExpandableField(
        'FLAGS + FRAGMENT OFFSET',
        field,
        content
    )
}
function renderSimpleField(
    title,
    field
) {

    const content = `

        <div class="label">
            RAW HEX
        </div>

        <div class="value">
            ${field.raw_hex}
        </div>

        <div class="label">
            RAW BINARY
        </div>

        <div class="value">
            ${field.raw_binary}
        </div>

        <br>

        <div>

            <strong>Value:</strong>

            ${field.value}

        </div>

        <br>

        <div>

            <strong>Meaning:</strong>

            ${field.meaning || 'N/A'}

        </div>
    `

    return createExpandableField(
        title,
        field,
        content
    )
}


/* ========================================================= */
/* AUTO FETCH */
/* ========================================================= */

setInterval(
    fetchPacket,
    3000
)