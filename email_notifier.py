from flask_mail import Mail, Message
import logging

logger = logging.getLogger(__name__)
mail = Mail()


def init_mail(app):
    app.config['MAIL_SERVER']         = 'smtp.gmail.com'
    app.config['MAIL_PORT']           = 587
    app.config['MAIL_USE_TLS']        = True
    app.config['MAIL_USE_SSL']        = False
    app.config['MAIL_USERNAME']       = 'zh455477@gmail.com'
    app.config['MAIL_PASSWORD']       = 'xfkhwbeysauwxafn'
    app.config['MAIL_DEFAULT_SENDER'] = ('INFRASCAN', 'zh455477@gmail.com')
    try:
        mail.init_app(app)
        logger.info("[EMAIL] Mail initialized successfully")
    except Exception as e:
        logger.error(f"[EMAIL] Mail init failed: {e}")


def send_alert_email(alert_type, equipment_name, ip, message, severity):
    try:
        recipient = 'zh455477@gmail.com'
        sender    = ('INFRASCAN', 'zh455477@gmail.com')

        color_map = {
            'critique':  '#dc3545',
            'important': '#fd7e14',
            'info':      '#0dcaf0',
        }
        color = color_map.get(severity, '#6c757d')

        subject = f"[{severity.upper()}] Network Alert — {equipment_name} ({ip})"

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
            <div style="background:{color}; color:white; padding:15px; border-radius:8px 8px 0 0;">
                <h2 style="margin:0;">&#9888;&#65039; Network Alert</h2>
                <span style="font-size:12px;">Severity: {severity.upper()}</span>
            </div>
            <div style="border:1px solid #ddd; padding:20px; border-radius:0 0 8px 8px;">
                <table style="width:100%; border-collapse:collapse;">
                    <tr>
                        <td style="padding:8px; font-weight:bold; color:#555;">Device:</td>
                        <td style="padding:8px;">{equipment_name}</td>
                    </tr>
                    <tr style="background:#f8f9fa;">
                        <td style="padding:8px; font-weight:bold; color:#555;">IP Address:</td>
                        <td style="padding:8px;">{ip}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px; font-weight:bold; color:#555;">Alert Type:</td>
                        <td style="padding:8px;">{alert_type}</td>
                    </tr>
                    <tr style="background:#f8f9fa;">
                        <td style="padding:8px; font-weight:bold; color:#555;">Message:</td>
                        <td style="padding:8px; color:{color};">{message}</td>
                    </tr>
                </table>
                <hr style="margin:20px 0;">
                <p style="color:#888; font-size:12px; text-align:center;">
                    INFRASCAN — Automated Alert System
                </p>
            </div>
        </div>
        """

        msg = Message(
            subject=subject,
            sender=sender,
            recipients=[recipient],
            html=html_body
        )
        mail.send(msg)
        logger.info(f"[EMAIL] Alert sent for {equipment_name} ({ip}) — {severity}")
        return True

    except Exception as e:
        logger.error(f"[EMAIL] Failed to send alert: {e}")
        return False
