import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blog = defineCollection({
	// Load Markdown and MDX files in the `src/content/blog/` directory.
	loader: glob({ base: './src/content/blog', pattern: '**/*.{md,mdx}' }),
	// Type-check frontmatter using a schema
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string(),
			// Transform string to Date object
			pubDate: z.coerce.date(),
			updatedDate: z.coerce.date().optional(),
			heroImage: image().optional(),
			difficulty: z.enum(['Easy', 'Medium', 'Hard', 'Insane']).optional(),
			postType: z.string().optional(), 
			osType: z.string().optional(),
		}),
});



const cheatsheets = defineCollection({
	// Load Markdown and MDX files in the `src/content/blog/` directory.
	loader: glob({ base: './src/content/cheatsheets', pattern: '**/*.{md,mdx}' }),
	// Type-check frontmatter using a schema
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string(),
			// Transform string to Date object
			pubDate: z.coerce.date(),
			updatedDate: z.coerce.date().optional(),
			heroImage: image().optional(),
			// difficulty: z.enum(['Easy', 'Medium', 'Hard', 'Insane']).optional(),
			// postType: z.string().optional(), 
			// osType: z.string().optional(),
		}),
});


const about = defineCollection({
	loader: glob({ base: './src/content/about', pattern: '**/*.{md,mdx}' }),
	// Type-check frontmatter using a schema
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string(),
			// Transform string to Date object
			// pubDate: z.coerce.date(),
			// updatedDate: z.coerce.date().optional(),
			heroImage: image().optional(),
		}),
});



export const collections = { blog, about, cheatsheets };
