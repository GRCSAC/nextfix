import { registerRoutes } from '../server.ts';
import { HttpError } from '../auth/context.ts';
import { featureRoutes, toServerRoutes } from './all.ts';

/*
 * Feature modules: exceptions, portfolio, schedule and digest. cli.ts imports this file, so the
 * routes below are live in every server it starts; each module's `migrations` are also applied
 * lazily on the features' own database handle (see featureDb in all.ts) until the store carries
 * them as versions 4 to 7. The ctx and route types live in core.ts and are re-exported here.
 *
 * Not wired here, because it needs the server's scan path: the scheduler.
 *   const scheduler = startScheduler({ db: featureDb(store.path), runScan, log, cachePath });
 *   server.on('close', () => scheduler.stop());
 */

export type { Role, Method, RouteUser, SettingsAccess, RouteContext, RouteResult, Route } from './core.ts';
export { FeatureError, ROLE_RANK, roleAllows, matchPattern, findRoute, settingsFor, makeContext, dispatch } from './core.ts';
export { featureMigrations, featureRoutes, applyFeatureMigrations, featureDb, closeFeatureDbs, toServerRoutes, exceptions, portfolio, schedule, digest } from './all.ts';
export type { ServerRoute, ServerRouteContext } from './all.ts';
export { startScheduler } from './schedule.ts';

registerRoutes(toServerRoutes(featureRoutes(), { mapError: (err) => new HttpError(err.status, err.message) }));
