#!/bin/sh

HOST=$1
shift

echo '## 200'
/testcase/200.py $HOST /								/html/index.html					$@
/testcase/200.py $HOST /index.html						/html/index.html					$@
/testcase/200.py $HOST /demo.html						/html/demo.html						$@
/testcase/200.py $HOST /hello.txt						/html/hello.txt						$@
/testcase/200.py $HOST /idapro.html						/html/idapro.html					$@
/testcase/200.py $HOST /idapro.txt						/html/idapro.txt					$@
/testcase/200.py $HOST /music/summer-walk-152722.mp3	/html/music/summer-walk-152722.mp3	$@
/testcase/200.py $HOST /music/good-night-160166.mp3		/html/music/good-night-160166.mp3	$@
/testcase/200.py $HOST /image/nycu_black.png			/html/image/nycu_black.png			$@
/testcase/200.py $HOST /image/nycu_blue.png				/html/image/nycu_blue.png			$@
/testcase/200.py $HOST /image/cat-6463284_1920.jpg		/html/image/cat-6463284_1920.jpg	$@
/testcase/200.py $HOST /index.html						/html/index.html					$@
/testcase/200.py $HOST /chinese.txt						/html/chinese.txt					$@
/testcase/200.py $HOST /%E4%B8%AD%E6%96%87%E6%AA%94%E5%90%8D.txt /html/中文檔名.txt			$@
/testcase/200.py $HOST '/?AAA=BBB'						/html/index.html					$@

echo ''
echo '## 301'
/testcase/301.py $HOST /music	$@
/testcase/301.py $HOST /image	$@

echo ''
echo '## NNN'
/testcase/NNN.py $HOST /no-exist	404		$@
/testcase/NNN.py $HOST /music/		403		$@
/testcase/NNN.py $HOST /image/		403		$@

echo ''
echo '## 501'
/testcase/501.py $HOST / AAA		$@
/testcase/501.py $HOST / BBB		$@
/testcase/501.py $HOST / OPTIONS	$@
/testcase/501.py $HOST / DELETE		$@

echo ''
echo '## Load Test'
wrk -t 4 -c 1200 -d 30s  --latency http://$HOST/idapro.html

