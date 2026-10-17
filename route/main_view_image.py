from .tool.func import *

async def main_view_image(name = ''):
    with get_db_connect() as conn:
        if '..' in name or name.startswith(('/', '\\')):
            return await re_error(conn, 0)

        if await acl_check('', 'render') != 1:
            name = re.sub(r'\.cache_v(?:[0-9]+)$', '', name)
            mime_type = re.search(r'([^.]+)$', name)
            if mime_type:
                mime_type = mime_type.group(1).lower()
                file_types = {
                    'png': 'image/png',
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'gif': 'image/gif',
                    'webp': 'image/webp',
                    'svg': 'image/svg+xml'
                }
                # SVG can carry script. Keep the real type so <img> renders it,
                # but never render it as a document.
                response = flask.send_from_directory(
                    './' + load_image_url(conn), name,
                    mimetype = file_types.get(mime_type, 'application/octet-stream'),
                    as_attachment = mime_type == 'svg' or mime_type not in file_types
                )
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
                return response
            else:
                return ''
        else:
            return await re_error(conn, 0)
