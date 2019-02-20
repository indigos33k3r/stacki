setenv STACK_ROOT /opt/stack

if ( -d $STACK_ROOT/bin ) then
	setenv PATH "${PATH}:$STACK_ROOT/bin:$STACK_ROOT/go/bin"
endif

if ( -d $STACK_ROOT/sbin ) then
	setenv PATH "${PATH}:$STACK_ROOT/sbin"
endif

if ( -d $STACK_ROOT/lib/pkgconfig ) then
	setenv PKG_CONFIG_PATH "${PKG_CONFIG_PATH}:$STACK_ROOT/lib/pkgconfig"
endif
