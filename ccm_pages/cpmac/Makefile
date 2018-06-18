UNAME_S := $(shell uname -s)
install_dep_command :=
ifeq ($(UNAME_S),Darwin)
	install_dep_command += CXX=clang++
endif
install_dep_command += npm install --no-package-lock


### Clean
clean:
	-sudo rm -R node_modules/
	-sudo rm -R platforms/
	-sudo rm -R hooks/
	-sudo rm -f package-lock.json

### Install local and global dependencies
install-dependencies:
	$(install_dep_command)

### Clean Install for EcmaScript6
clean-install:
	make clean
	make install-dependencies
	./prepare-hook.sh
	patch -p0 < nodeify_temporary_patch.patch

### Run App iOS
run-ios:
	tns run ios

### Clean Run App iOS
clean-run-ios:
	make clean-install
	tns run ios

### Run App Android
run-android:
	tns run android

### Clean Run App Android
clean-run-android:
	make clean-install
	tns run android

### Test App iOS
test-ios:
	tns test ios

### Clean Test App iOS
clean-test-ios:
	make clean-install
	tns test ios

### Test App Android
test-android:
	tns test android

### Clean Test App Android
clean-test-android:
	make clean-install
	tns test android
