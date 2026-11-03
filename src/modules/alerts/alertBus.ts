import { EventEmitter } from 'node:events';

// What we publish to live listeners (the SSE stream). Kept as plain data.
export interface AlertView {
  id: string;
  ruleId: string;
  ruleName: string;
  status: string;
  severity: string;
  title: string;
  groupKey: string;
  eventCount: number;
  firstEventAt: Date;
  lastEventAt: Date;
  createdAt: Date;
}

export interface AlertMessage {
  type: 'alert.created' | 'alert.updated';
  alert: AlertView;
}

// A tiny in-process publish/subscribe channel. The rules engine publishes; every open SSE
// connection subscribes. It only works inside ONE API process. To run several instances you
// would replace it with Postgres LISTEN/NOTIFY or Redis pub/sub; the rest of the code would
// not change because it only talks to publish() and subscribe().
class AlertBus {
  private emitter = new EventEmitter();

  constructor() {
    this.emitter.setMaxListeners(0); // one listener per open stream; we cap streams ourselves
  }

  publish(message: AlertMessage) {
    this.emitter.emit('alert', message);
  }

  subscribe(listener: (message: AlertMessage) => void): () => void {
    this.emitter.on('alert', listener);
    return () => this.emitter.off('alert', listener);
  }

  get listenerCount() {
    return this.emitter.listenerCount('alert');
  }
}

export const alertBus = new AlertBus();
