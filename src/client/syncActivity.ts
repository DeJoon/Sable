export type SyncActivity = {
  visible: boolean;
  callActive: boolean;
  drainingPush: boolean;
};

export type SyncAction = 'start' | 'stop' | 'none';

export const nextSyncAction = (paused: boolean, activity: SyncActivity): SyncAction => {
  const wanted = activity.visible || activity.callActive || activity.drainingPush;
  if (!paused && !wanted) return 'stop';
  if (paused && wanted) return 'start';
  return 'none';
};
