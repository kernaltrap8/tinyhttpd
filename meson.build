project('tinyhttpd', 'cpp',
  version : '0.10.0',
  default_options : ['warning_level=3', 'cpp_std=c++17'])
link_args = ['-lssl', '-lcrypto']
executable('tinyhttpd',
           'src/tinyhttpd.cpp',
           install : true, link_args: link_args)
