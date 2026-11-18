import {build} from 'esbuild';
import {readFile,writeFile,mkdir,copyFile} from 'node:fs/promises';
await mkdir('.internal/dist',{recursive:true});
const js=await build({entryPoints:['src/app.js'],bundle:true,write:false,minify:true,target:'es2022'});
const html=(await readFile('src/index.html','utf8')).replace('/* STYLE */',await readFile('src/style.css','utf8')).replace('/* SCRIPT */',()=>js.outputFiles[0].text.replaceAll('</script','<\\/script'));
await writeFile('.internal/dist/index.html',html);await copyFile('CNAME','.internal/dist/CNAME');
console.log('Built standalone HTML:',Buffer.byteLength(html),'bytes');
