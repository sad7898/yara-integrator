ALLOWED_EXTENSIONS = {'apk','txt','pdf'}
def is_file_allowed(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS