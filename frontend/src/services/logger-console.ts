/**
 * Centralized logging service for debugging and error tracking
 *
 * Usage:
 *   logger.debug('Component', 'Operation started', { data });
 *   logger.info('Component', 'User action', { action });
 *   logger.warn('Component', 'Unexpected state', { state });
 *   logger.error('Component', 'Operation failed', error, { context });
 */

type LogLevel = "debug" | "info" | "warn" | "error";

interface LogContext {
  [key: string]: any;
}

class Logger {
  private isDevelopment: boolean;
  private enabledLevels: Set<LogLevel>;

  constructor() {
    this.isDevelopment = import.meta.env.DEV || import.meta.env.MODE === "development";

    // In production, only log warnings and errors
    // In development, log everything
    this.enabledLevels = this.isDevelopment ? new Set(["debug", "info", "warn", "error"]) : new Set(["warn", "error"]);
  }

  private formatMessage(component: string, message: string, context?: LogContext): string {
    const timestamp = new Date().toISOString();
    const contextStr = context ? ` | ${JSON.stringify(context)}` : "";
    return `[${timestamp}] [${component}] ${message}${contextStr}`;
  }

  private shouldLog(level: LogLevel): boolean {
    return this.enabledLevels.has(level);
  }

  debug(component: string, message: string, context?: LogContext): void {
    if (this.shouldLog("debug")) {
      console.debug(this.formatMessage(component, message, context));
    }
  }

  info(component: string, message: string, context?: LogContext): void {
    if (this.shouldLog("info")) {
      console.info(this.formatMessage(component, message, context));
    }
  }

  warn(component: string, message: string, context?: LogContext): void {
    if (this.shouldLog("warn")) {
      console.warn(this.formatMessage(component, message, context));
    }
  }

  error(component: string, message: string, error?: any, context?: LogContext): void {
    if (this.shouldLog("error")) {
      const errorInfo = error
        ? {
            message: error.message,
            stack: error.stack,
            response: error.response?.data,
            status: error.response?.status,
            code: error.code,
            ...context,
          }
        : context;

      console.error(this.formatMessage(component, message, errorInfo));

      // Log the actual error object separately for better dev tools support
      if (error) {
        console.error(error);
      }
    }
  }

  /**
   * Log HTTP request
   */
  request(component: string, method: string, url: string, data?: any): void {
    if (this.shouldLog("debug")) {
      this.debug(component, `HTTP ${method} ${url}`, { data });
    }
  }

  /**
   * Log HTTP response
   */
  response(component: string, method: string, url: string, status: number, data?: any): void {
    if (this.shouldLog("debug")) {
      this.debug(component, `HTTP ${method} ${url} - ${status}`, { data });
    }
  }

  /**
   * Log user action
   */
  action(component: string, action: string, details?: LogContext): void {
    if (this.shouldLog("info")) {
      this.info(component, `Action: ${action}`, details);
    }
  }

  /**
   * Log state change
   */
  stateChange(component: string, from: any, to: any, reason?: string): void {
    if (this.shouldLog("debug")) {
      this.debug(component, `State change: ${from} → ${to}`, { reason });
    }
  }

  /**
   * Set log level dynamically (useful for debugging)
   */
  setLogLevel(levels: LogLevel[]): void {
    this.enabledLevels = new Set(levels);
    this.info("Logger", `Log levels updated`, { levels });
  }

  /**
   * Enable all logging (for debugging)
   */
  enableAll(): void {
    this.setLogLevel(["debug", "info", "warn", "error"]);
  }

  /**
   * Disable all logging except errors
   */
  errorsOnly(): void {
    this.setLogLevel(["error"]);
  }
}

// Export singleton instance
export const logger = new Logger();

// Expose logger globally for debugging in browser console
if (typeof window !== "undefined") {
  (window as any).logger = logger;
}

export default logger;
