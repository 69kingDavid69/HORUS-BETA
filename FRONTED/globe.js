/* ══════════════════════════════════════════════════════
   HORUS — Globe 3D, FAB Chatbot & Console Typewriter
   Extracted from index.html inline <script>
   ══════════════════════════════════════════════════════ */

(function () {
    const globeCanvas = document.getElementById('globeCanvas');
    if (!globeCanvas) return;

    const compactBackgroundQuery = window.matchMedia('(max-width: 1450px)');
    const mobileBackgroundQuery = window.matchMedia('(max-width: 640px)');

    function getSceneConfig() {
        const backgroundMode = compactBackgroundQuery.matches;
        const mobileMode = mobileBackgroundQuery.matches;

        if (backgroundMode) {
            return {
                width: window.innerWidth,
                height: window.innerHeight,
                cameraZ: mobileMode ? 3.4 : 3.15,
                groupX: mobileMode ? -0.18 : -0.42,
                groupY: mobileMode ? -0.52 : -0.34,
                groupScale: mobileMode ? 1.34 : 1.6,
                backgroundMode
            };
        }

        return {
            width: Math.round(window.innerWidth * 0.45),
            height: window.innerHeight,
            cameraZ: 3.0,
            groupX: 0,
            groupY: 0,
            groupScale: 1,
            backgroundMode
        };
    }

    const scene = new THREE.Scene();
    const initialConfig = getSceneConfig();
    const camera = new THREE.PerspectiveCamera(45, initialConfig.width / initialConfig.height, 0.1, 1000);
    camera.position.z = initialConfig.cameraZ;

    const renderer = new THREE.WebGLRenderer({ canvas: globeCanvas, antialias: true, alpha: true });
    renderer.setSize(initialConfig.width, initialConfig.height, false);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);

    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Cyber texture: hex grid + continents as circuit traces
    function makeCyberTexture(size) {
        const c = document.createElement('canvas');
        c.width = size; c.height = size;
        const ctx = c.getContext('2d');

        // Dark base
        ctx.fillStyle = '#020a10';
        ctx.fillRect(0, 0, size, size);

        // Very thin cyan grid lines
        ctx.strokeStyle = 'rgba(34,211,238,0.18)';
        ctx.lineWidth = 0.8;
        const step = size / 28;
        for (let x = 0; x <= size; x += step) {
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, size); ctx.stroke();
        }
        for (let y = 0; y <= size; y += step) {
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(size, y); ctx.stroke();
        }

        // Diagonal circuit lines
        ctx.strokeStyle = 'rgba(34,211,238,0.08)';
        ctx.lineWidth = 0.5;
        for (let i = -size; i < size * 2; i += step * 2.5) {
            ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i + size, size); ctx.stroke();
        }

        // Blinking city nodes (bright points)
        const nodes = [
            [0.22, 0.22], [0.15, 0.30], [0.27, 0.54], [0.48, 0.18], [0.52, 0.20],
            [0.50, 0.30], [0.60, 0.18], [0.68, 0.22], [0.75, 0.28], [0.80, 0.20],
            [0.72, 0.62], [0.30, 0.14], [0.20, 0.40], [0.56, 0.38], [0.84, 0.26]
        ];
        nodes.forEach(([nx, ny]) => {
            const x = nx * size, y = ny * size;
            // Outer glow
            const grd = ctx.createRadialGradient(x, y, 0, x, y, 10);
            grd.addColorStop(0, 'rgba(34,211,238,0.9)');
            grd.addColorStop(0.3, 'rgba(34,211,238,0.4)');
            grd.addColorStop(1, 'rgba(34,211,238,0)');
            ctx.beginPath();
            ctx.arc(x, y, 10, 0, Math.PI * 2);
            ctx.fillStyle = grd;
            ctx.fill();
            // Center point
            ctx.beginPath();
            ctx.arc(x, y, 2, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.fill();
        });

        // Connection lines between nodes (circuit style)
        ctx.strokeStyle = 'rgba(34,211,238,0.3)';
        ctx.lineWidth = 0.8;
        const connections = [[0, 1], [1, 2], [0, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [8, 9], [9, 10], [3, 11], [1, 12], [5, 13], [8, 14]];
        connections.forEach(([a, b]) => {
            ctx.beginPath();
            ctx.moveTo(nodes[a][0] * size, nodes[a][1] * size);
            ctx.lineTo(nodes[b][0] * size, nodes[b][1] * size);
            ctx.stroke();
        });

        return new THREE.CanvasTexture(c);
    }

    // Main sphere (radius 0.65)
    const earthTex = makeCyberTexture(2048);
    const earth = new THREE.Mesh(
        new THREE.SphereGeometry(0.65, 80, 80),
        new THREE.MeshPhongMaterial({
            map: earthTex,
            emissiveMap: earthTex,
            emissive: new THREE.Color(0x0a1520),
            emissiveIntensity: 0.6,
            specular: new THREE.Color(0x0d6677),
            shininess: 6,
        })
    );
    globeGroup.add(earth);

    // Wireframe overlay
    const wireMesh = new THREE.Mesh(
        new THREE.SphereGeometry(0.651, 28, 28),
        new THREE.MeshBasicMaterial({
            color: 0x22d3ee,
            wireframe: true,
            transparent: true,
            opacity: 0.06,
        })
    );
    globeGroup.add(wireMesh);

    // Inner glow atmosphere
    const atm = new THREE.Mesh(
        new THREE.SphereGeometry(0.69, 64, 64),
        new THREE.MeshPhongMaterial({
            color: 0x22d3ee,
            transparent: true,
            opacity: 0.07,
            side: THREE.FrontSide,
            depthWrite: false,
        })
    );
    globeGroup.add(atm);

    // Outer halo
    const halo = new THREE.Mesh(
        new THREE.SphereGeometry(0.77, 64, 64),
        new THREE.MeshPhongMaterial({
            color: 0x22d3ee,
            transparent: true,
            opacity: 0.035,
            side: THREE.BackSide,
            depthWrite: false,
        })
    );
    globeGroup.add(halo);

    // Orbital rings (scaled)
    function makeRing(radius, tube, color, opacity, tiltX, tiltZ) {
        const ring = new THREE.Mesh(
            new THREE.TorusGeometry(radius, tube, 6, 120),
            new THREE.MeshBasicMaterial({ color, transparent: true, opacity })
        );
        ring.rotation.x = tiltX;
        ring.rotation.z = tiltZ;
        globeGroup.add(ring);
        return ring;
    }
    const ring1 = makeRing(0.86, 0.003, 0x22d3ee, 0.55, Math.PI / 2, 0.3);
    const ring2 = makeRing(0.96, 0.002, 0x60a5fa, 0.35, Math.PI / 2.5, -0.5);
    const ring3 = makeRing(1.05, 0.002, 0x22d3ee, 0.20, Math.PI / 1.8, 0.8);

    // Orbital particles (500, spread across the screen)
    const orbGeo = new THREE.BufferGeometry();
    const orbCount = 500;
    const orbPos = new Float32Array(orbCount * 3);
    const orbAngles = new Float32Array(orbCount);
    const orbRadii = new Float32Array(orbCount);
    const orbSpeeds = new Float32Array(orbCount);
    const orbY = new Float32Array(orbCount);
    for (let i = 0; i < orbCount; i++) {
        orbAngles[i] = Math.random() * Math.PI * 2;
        orbRadii[i] = 0.9 + Math.random() * 3.2;   // 0.9 → 4.1 unidades
        orbSpeeds[i] = (Math.random() * 0.003 + 0.0005) * (Math.random() > 0.5 ? 1 : -1);
        orbY[i] = (Math.random() - 0.5) * 6.0; // wide vertical spread
        orbPos[i * 3] = Math.cos(orbAngles[i]) * orbRadii[i];
        orbPos[i * 3 + 1] = orbY[i];
        orbPos[i * 3 + 2] = Math.sin(orbAngles[i]) * orbRadii[i];
    }
    orbGeo.setAttribute('position', new THREE.BufferAttribute(orbPos, 3));
    const orbMat = new THREE.PointsMaterial({
        color: 0x22d3ee, size: 0.038,
        transparent: true, opacity: 0.85
    });
    const orbPoints = new THREE.Points(orbGeo, orbMat);
    globeGroup.add(orbPoints);

    // Lights
    const keyLight = new THREE.DirectionalLight(0x88ddff, 1.2);
    keyLight.position.set(4, 2, 4);
    scene.add(keyLight);
    const rimLight = new THREE.DirectionalLight(0x22d3ee, 0.3);
    rimLight.position.set(-4, -1, -3);
    scene.add(rimLight);
    scene.add(new THREE.AmbientLight(0x0a1520, 5.0));

    // Mouse interaction
    let targetX = 0, targetY = 0, mouseX = 0, mouseY = 0;
    document.addEventListener('mousemove', function (e) {
        mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
        mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    });

    function applySceneLayout() {
        const config = getSceneConfig();
        globeCanvas.dataset.backgroundMode = config.backgroundMode ? 'true' : 'false';
        camera.aspect = config.width / config.height;
        camera.position.z = config.cameraZ;
        camera.updateProjectionMatrix();
        globeGroup.position.set(config.groupX, config.groupY, 0);
        globeGroup.scale.setScalar(config.groupScale);
        renderer.setSize(config.width, config.height, false);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    }

    applySceneLayout();

    // Animation loop
    let t = 0;
    function animate() {
        requestAnimationFrame(animate);
        t += 0.012;

        targetX += (mouseX * 0.012 - targetX) * 0.04;
        targetY += (mouseY * 0.25 - targetY) * 0.04;

        earth.rotation.y += 0.0012 + targetX;
        earth.rotation.x += (targetY - earth.rotation.x) * 0.03;
        wireMesh.rotation.y = earth.rotation.y;
        wireMesh.rotation.x = earth.rotation.x;

        // Rings rotate at different speeds
        ring1.rotation.z += 0.003;
        ring2.rotation.z -= 0.002;
        ring3.rotation.y += 0.0015;

        // Orbital particles
        const positions = orbGeo.attributes.position.array;
        for (let i = 0; i < orbCount; i++) {
            orbAngles[i] += orbSpeeds[i];
            positions[i * 3] = Math.cos(orbAngles[i]) * orbRadii[i];
            positions[i * 3 + 1] = orbY[i];
            positions[i * 3 + 2] = Math.sin(orbAngles[i]) * orbRadii[i];
        }
        orbGeo.attributes.position.needsUpdate = true;

        // Particle opacity pulse
        orbMat.opacity = 0.55 + Math.sin(t * 2.5) * 0.3;

        renderer.render(scene, camera);
    }
    animate();

    window.addEventListener('resize', applySceneLayout);
    compactBackgroundQuery.addEventListener?.('change', applySceneLayout);
    mobileBackgroundQuery.addEventListener?.('change', applySceneLayout);

    // ── FAB toggle ──
    const fabBtn = document.getElementById('chatFabBtn');
    const fabPanel = document.getElementById('chatFabPanel');
    const fabClose = document.getElementById('chatFabClose');

    function openChat() {
        fabPanel.classList.add('active');
        fabPanel.setAttribute('aria-hidden', 'false');
        fabBtn.classList.add('chat-fab--open');
    }
    function closeChat() {
        fabPanel.classList.remove('active');
        fabPanel.setAttribute('aria-hidden', 'true');
        fabBtn.classList.remove('chat-fab--open');
    }
    if (fabBtn) fabBtn.addEventListener('click', function () {
        fabPanel.classList.contains('active') ? closeChat() : openChat();
    });
    if (fabClose) fabClose.addEventListener('click', closeChat);

    // Close chat when clicking outside
    document.addEventListener('click', function (e) {
        if (fabPanel && fabPanel.classList.contains('active')) {
            if (!fabPanel.contains(e.target) && !fabBtn.contains(e.target)) {
                closeChat();
            }
        }
    });
})();

// ── Console Typewriter Effect ──
(function () {
    const subtitleTexts = [
        "Descubrimiento de red: Localización de nodos activos en infraestructura.",
        "Identificación de servicios: Análisis de puertos y protocolos abiertos.",
        "Detección de SO: Extracción de huella digital del sistema.",
        "Pruebas de credenciales: Verificación de integridad de accesos."
    ];
    const typingEl = document.getElementById("heroTypingText");
    let subIndex = 0;
    let charIndex = 0;
    let isDeleting = false;

    function typeConsole() {
        if (!typingEl) return;
        const currentText = subtitleTexts[subIndex];

        if (isDeleting) {
            typingEl.textContent = currentText.substring(0, charIndex - 1);
            charIndex--;
        } else {
            typingEl.textContent = currentText.substring(0, charIndex + 1);
            charIndex++;
        }

        let speed = isDeleting ? 25 : 45;

        if (!isDeleting && charIndex === currentText.length) {
            speed = 3000; // Lapso de 3 segundos
            isDeleting = true;
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            let nextIndex = Math.floor(Math.random() * subtitleTexts.length);
            if (nextIndex === subIndex && subtitleTexts.length > 1) {
                nextIndex = (nextIndex + 1) % subtitleTexts.length;
            }
            subIndex = nextIndex;
            speed = 400;
        }
        setTimeout(typeConsole, speed);
    }
    if (typingEl) setTimeout(typeConsole, 1000);
})();
