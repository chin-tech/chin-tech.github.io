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
            resultsDiv.innerHTML = dataResults.map(item => `
                <a href="${item.url}" class="block group border border-primary/10 bg-base-200/50 p-4 rounded-xl hover:border-primary/50 transition-all">
                    <div class="flex justify-between items-start mb-2">
                        <h2 class="text-xl font-bold text-primary italic uppercase">${item.meta.title}</h2>
                        <span class="text-[10px] opacity-40 uppercase">${item.meta.date || ''}</span>
                    </div>
                    
                    <p class="text-sm opacity-70 line-clamp-2 mb-4 font-sans">${item.excerpt}</p>
                    
                    <div class="flex items-center gap-4 border-t border-primary/5 pt-3">
                        <div class="flex items-center gap-2">
                            <span class="badge badge-primary badge-sm text-[10px] font-bold tracking-tighter">
                                ${item.meta.type || 'INTEL'}
                            </span>
                            <span class="badge badge-outline badge-sm text-[10px] opacity-60">
                                ${item.meta.os || 'GENERIC'}
                            </span>
                        </div>
                    </div>
                </a>
            `).join('');
        });
    }

    // Initialize on load
    initSearch();
    // Re-initialize on Astro page navigation
    document.addEventListener('astro:after-swap', initSearch);
