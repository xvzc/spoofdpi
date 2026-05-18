// Wait for the HTML document to be fully loaded and parsed
// before running any script that interacts with the DOM.
window.addEventListener('DOMContentLoaded', (event) => {
    
    const canvas = document.getElementById('matrix');
    const context = canvas.getContext('2d');

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    // --- Set the initial background color ---
    // This matches the HTML body background color.
    context.fillStyle = '#14151a'; // hsl(230, 13%, 9%)
    context.fillRect(0, 0, canvas.width, canvas.height);


    const katakana = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホ모ヨョロヲゴゾドボポヴッン';
    const latin = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const nums = '0123456789';

    const alphabet = katakana + latin + nums; // Added latin back

    const fontSize = 16;
    const columns = canvas.width / fontSize;

    const rainDrops = [];

    for (let x = 0; x < columns; x++) {
        const r = Math.random()
        // Start at a random negative (off-screen) row, scaled by screen height.
        rainDrops[x] = Math.floor(r*10 * (canvas.height / fontSize) * -1);
    }

    // --- [MODIFIED] Animation Loop setup ---

    let lastTime = 0;
    const interval = 30; // Target 30ms interval (approx 33 FPS)
    let timer = 0;

    // We define a new 'animate' function that includes the 'draw' logic
    // and also handles throttling to match the original speed.
    const animate = (timestamp) => {
        // timestamp is provided by requestAnimationFrame
        const deltaTime = timestamp - lastTime;
        lastTime = timestamp;

        if (timer > interval) {
            // --- This is the original 'draw()' logic ---

            // [MODIFIED] Add dithering to prevent color banding in Firefox
            // We slightly randomize the alpha channel on every frame.
            const baseAlpha = 0.2; // Controls the trail length
            const ditherAlpha = baseAlpha + (Math.random() * 0.05871); // Add 0-2% noise

            const gradient = context.createLinearGradient(0, 0, 0, canvas.height);
            // Start color: dark blue/grey fade (with dither)
            gradient.addColorStop(0, `rgba(20, 21, 26, ${ditherAlpha})`); 
            // End color: pure black fade (with dither)
            gradient.addColorStop(1, `rgba(0, 0, 0, ${ditherAlpha})`);
            
            context.fillStyle = gradient;
            context.fillRect(0, 0, canvas.width, canvas.height);

            context.fillStyle = '#0F0'; // Green text
            context.font = fontSize + 'px monospace';

            for (let i = 0; i < rainDrops.length; i++) {
                if (rainDrops[i] < 0 && Math.random() > 0.975) {
                    rainDrops[i] = 1 + Math.round(Math.random());
                }

                const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                const yPos = rainDrops[i] * fontSize;

                if (yPos > 0) {
                    context.fillText(text, i * fontSize, yPos);
                }

                if (yPos > canvas.height && Math.random() > 0.975) {
                    rainDrops[i] = Math.round(Math.random());
                }

                rainDrops[i]++;
            }
            // --- End of original 'draw()' logic ---
            timer = 0; // Reset timer
        } else {
            timer += deltaTime;
        }

        // Request the *next* animation frame, creating a loop.
        requestAnimationFrame(animate);
    }

    // [MODIFIED] Start the animation using requestAnimationFrame
    // instead of setInterval.
    requestAnimationFrame(animate);

    // Handle window resize
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        // A full resize implementation would need to rebuild 'rainDrops'
        // based on the new 'columns' count.
    });
});
