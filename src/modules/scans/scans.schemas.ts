import { z } from 'zod';
import { paginationQuery } from '../../lib/pagination.js';

// `target` is an exact match, so a target's scan history (for trends) can be fetched.
export const listScansQuery = paginationQuery.extend({ target: z.string().max(2048).optional() });
export type ListScansQuery = z.infer<typeof listScansQuery>;
