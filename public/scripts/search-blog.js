async function initSearch() {
        const input = document.querySelector('#search-input');
        const resultsDiv = document.querySelector('#results');
        let pagefind;

        // 1. Initialize Pagefind API
        try {
            pagefind = await import("/pagefind/pagefind.js");
            await pagefind.init();
        } catch (e) {
            console.error("Critical: Pagefind failed to load", e);
            resultsDiv.innerHTML = '<p class="text-error">[!] SYSTEM ERROR: SEARCH ENGINE OFFLINE</p>';
            return;
        }

        input.addEventListener('input', async (e) => {
            const query = e.target.value.trim();
            
            if (query.length < 2) {
                resultsDiv.innerHTML = "";
                return;
            }

            // 2. Perform Search
            const search = await pagefind.search(query);
            
            // Handle 0 results immediately
            if (!search.results.length) {
                resultsDiv.innerHTML = '<p class="opacity-50 text-xs text-error">[!] QUERY RETURNED NULL: NO INTEL FOUND</p>';
                return;
            }

            resultsDiv.innerHTML = '<p class="opacity-50 text-xs animate-pulse">[ ACCESSING DATABASE... ]</p>';
            
            // 3. Resolve Data
            // We only take the top 5-10 for speed
            const dataResults = await Promise.all(
                search.results.slice(0, 20).map(r => r.data())
            );

            // 4. Render Results
resultsDiv.innerHTML = dataResults.map(item => {
    const thumb = item.meta.image;
    
    // Ensure pathing is correct
    let imageSrc = thumb;
    if (thumb && !thumb.startsWith('http')) {
        imageSrc = thumb.startsWith('/') ? thumb : `/${thumb}`;
    }

    return `
        <a href="${item.url}" class="flex flex-col md:flex-row gap-6 group border border-primary/10 bg-base-200/50 p-5 rounded-xl hover:border-primary/50 transition-all mb-6">
            
            <div class="w-full md:w-40 h-24 shrink-0 overflow-hidden rounded-lg border border-primary/10 bg-base-300 flex items-center justify-center relative">
                ${imageSrc ? `
                    <img 
                        src="${imageSrc}" 
                        alt="" 
                        class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500 relative z-10" 
                        onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';"
                    />
                    <div class="absolute inset-0 hidden items-center justify-center bg-base-300" style="display: none;">
                        <span class="opacity-20 text-[10px] uppercase font-mono">Offline</span>
                    </div>
                ` : `
                    <span class="text-[10px] opacity-20 uppercase font-mono">No Intel</span>
                `}
            </div>

            <div class="flex-grow">
                <div class="flex justify-between items-start mb-2">
                    <h2 class="text-xl font-bold text-primary italic uppercase tracking-tighter">${item.meta.title}</h2>
<span class="badge badge-outline badge-sm text-[10px] text-primary font-mono tracking-tighter border-primary/30">
    ${item.meta.date || ''}
</span>
                </div>
                
                <p class="text-sm opacity-70 line-clamp-2 mb-4 font-sans leading-relaxed">
                    ${item.excerpt}
                </p>
                
                <div class="flex items-center justify-between border-t border-primary/5 pt-3">
                    <div class="flex items-center gap-3">
                        
                        ${item.meta.type ? `
                            <span class="badge badge-primary badge-sm text-[10px] font-bold py-3" data-type="${item.meta.type}">
                                ${item.meta.type}
                            </span>
                        ` : ''}

                        ${item.meta.os ? `
                            <span class="badge badge-outline badge-sm text-[10px] opacity-70 py-3" data-os="${item.meta.os}">
                                ${item.meta.os}
                            </span>
                        ` : ''}

                    </div>

                    ${item.meta.difficulty ? `
                        <span class="text-[10px] font-mono uppercase opacity-40 tracking-widest">
                            ${item.meta.difficulty}
                        </span>
                    ` : ''}
                </div>
            </div>
        </a>
    `;
}).join('');
        });
    }

    // Initialize on load
    initSearch();
    // Re-initialize on Astro page navigation
    document.addEventListener('astro:after-swap', initSearch);
