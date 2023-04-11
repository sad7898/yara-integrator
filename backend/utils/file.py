ALLOWED_EXTENSIONS = {'rar','zip', 'tar', 'gz', 'bz2', 'xz', 'tar.gz', 'tar.bz2', 'tar.xz','apk'} # List of common archive file extensions

def is_file_allowed(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def get_file_extension(filename):
    return  filename.rsplit('.', 1)[1].lower()

def is_file_archive(filename):
    return is_file_allowed(filename) and filename.rsplit('.', 1)[1].lower() != 'txt'
