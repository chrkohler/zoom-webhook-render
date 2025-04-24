# Configuración de Gunicorn para Render
bind = "0.0.0.0:10000"
workers = 2
timeout = 120
accesslog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'