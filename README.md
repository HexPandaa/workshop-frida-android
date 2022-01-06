# Workshop Frida

## Setup

### Android Studio

Install Android Studio and create an emulator running Android 7.1.1 x86, without Google APIs. This last point is important as it ensures the emulator is rooted.

### Frida

Create a venv.

```bash
python3 -m venv venv
cd venv
source ./venv/bin/activate
```

Install Frida through pip. 

```bash
pip3 install frida frida-tools
```

> At the time of writing, Frida was broken on Python 3.10, Python 3.9.9 and below worked.

### Reversing tools

Download jadx-gui from [here](https://github.com/skylot/jadx/releases).

## Hands-on

### Recon

#### List packages installed on the device

```bash
adb shell pm list packages -f
```

#### List running processes and installed applications

```bash
frida-ps -U -a -i
```

### Exploitation

#### Hooking a system function

```javascript
Java.perform(function() {
		console.log("[ * ] Overriding functions");
	 
		const System = Java.use("java.lang.System");
		const sysMyFunction = System.myFunction;
	 
		sysMyFunction.implementation = function() {
			console.log("Hooking myFunction");
			const ret = sysMyFunction.call();
			console.log("Return value: " + ret);
			return ret;
		}
	}
)
```

#### Hooking an overloaded function

```javascript
	Java.perform(function() {
		console.log("[ * ] Overriding functions");
	 
		const MyClass = Java.use("com.appsomething.MyClass");
		const targetFunction = MyClass.target.overload("int", "java.lang.String");
	 
		targetFunction.implementation = function(val_i, val_s) {
			console.log("Hooking target");
			console.log("Called with: " + val_i + ", " + val_s);
			const ret = targetFunction.call(this, val_i, val_s);
			console.log("Return value: " + ret);
			return ret;
		}
	}
)
```

> Here are some Frida base types: "int", "float", "[B" (byte array).

## Resources

- [Frida official Android example](https://frida.re/docs/examples/android/)
- https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting/frida-tutorial/frida-tutorial-1
- https://braincoke.fr/blog/2021/03/android-reverse-engineering-for-beginners-frida/#static-analysis-reminder
