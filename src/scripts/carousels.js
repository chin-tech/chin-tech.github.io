const startCarousels = () => {
    function initInfiniteCarousel(id, speed) {
        const carousel = document.getElementById(id);
        if (!carousel) return;

        let interval;
        const step = 1;
        
        function stepScroll() {
            // Reset scroll position halfway through the content width
            // to create the illusion of an infinite loop
            if (carousel.scrollLeft >= (carousel.scrollWidth / 2)) {
                carousel.scrollLeft = 0;
            } else {
                carousel.scrollLeft += step;
            }
        }

        const start = () => {
            interval = setInterval(stepScroll, speed);
        };

        const stop = () => {
            clearInterval(interval);
        };

        start();

        carousel.addEventListener('mouseenter', stop);
        carousel.addEventListener('mouseleave', start);
        
        document.addEventListener('astro:before-preparation', stop);
    }

    initInfiniteCarousel('post-carousel', 40);
    initInfiniteCarousel('skills-carousel', 20);
};

startCarousels();
document.addEventListener('astro:after-swap', startCarousels);
