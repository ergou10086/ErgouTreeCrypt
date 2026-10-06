package hbnu.project.ergoutreecrypt.android;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 测试 APK 独立进程的虚拟 SAF 提供者，使用平台和 Java API，不暴露真实文件。 */
public final class SplitTestDocumentsProvider extends ContentProvider {
    private final Map<String,byte[]> files=new HashMap<>();

    /** 初始化固定目录及分卷，无第三方运行时依赖。 */
    @Override public boolean onCreate() {
        files.put("root/A/same.bin.ergou.0",new byte[]{0,1,2,3,4});
        files.put("root/A/same.bin.ergou.1",new byte[]{5,6,7,8,9});
        files.put("root/B/same.bin.ergou.0",new byte[]{10,11,12,13,14});
        files.put("root/B/same.bin.ergou.1",new byte[]{15,16,17,18,19});
        byte[] manifest="format=EGTC-SPLIT-1\ncount=2\nbytes=10\nchunkSize=5\n".getBytes(StandardCharsets.UTF_8);
        files.put("root/A/same.bin.ergou.volumes",manifest);files.put("root/B/same.bin.ergou.volumes",manifest);
        return true;
    }

    /** @param uri 文档 URI @return 文档 ID */
    private String id(Uri uri) {
        List<String> segments=uri.getPathSegments();return segments.get(segments.indexOf("document")+1);
    }

    /** 查询单个文档或直接子文档，故意不提供真实路径列。 */
    @Override public Cursor query(Uri uri,String[] projection,String selection,String[] args,String sort) {
        MatrixCursor cursor=new MatrixCursor(projection==null?new String[]{Document.COLUMN_DOCUMENT_ID,Document.COLUMN_DISPLAY_NAME,Document.COLUMN_MIME_TYPE,Document.COLUMN_SIZE}:projection);
        String documentId=id(uri);
        if(uri.getLastPathSegment().equals("children")) {
            if(documentId.equals("root")){add(cursor,"root/A");add(cursor,"root/B");}
            else for(String key:new java.util.TreeSet<>(files.keySet()))if(key.substring(0,key.lastIndexOf('/')).equals(documentId))add(cursor,key);
        } else add(cursor,documentId);
        return cursor;
    }

    /** @param cursor 结果集 @param documentId 文档 ID */
    private void add(MatrixCursor cursor,String documentId) {
        MatrixCursor.RowBuilder row=cursor.newRow();
        for(String column:cursor.getColumnNames()) {
            Object value=null;
            if(column.equals(Document.COLUMN_DOCUMENT_ID))value=documentId;
            else if(column.equals(Document.COLUMN_DISPLAY_NAME))value=documentId.substring(documentId.lastIndexOf('/')+1);
            else if(column.equals(Document.COLUMN_MIME_TYPE))value=files.containsKey(documentId)?"application/octet-stream":Document.MIME_TYPE_DIR;
            else if(column.equals(Document.COLUMN_SIZE))value=files.containsKey(documentId)?files.get(documentId).length:0;
            row.add(value);
        }
    }

    /** 通过管道读取分卷内容，模拟没有本地路径的文档提供者。 */
    @Override public ParcelFileDescriptor openFile(Uri uri,String mode) throws FileNotFoundException {
        if(!mode.equals("r"))throw new FileNotFoundException(mode);
        byte[] bytes=files.get(id(uri));if(bytes==null)throw new FileNotFoundException(uri.toString());
        try {
            ParcelFileDescriptor[] pipe=ParcelFileDescriptor.createPipe();
            new Thread(()->{try(var out=new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])){out.write(bytes);}catch(IOException error){throw new RuntimeException(error);}},"split-test-provider").start();
            return pipe[0];
        } catch(IOException error){throw new FileNotFoundException(error.toString());}
    }

    /** 查询测试文档类型。 */ @Override public String getType(Uri uri){return "application/octet-stream";}
    /** 测试提供者只读。 */ @Override public Uri insert(Uri uri,ContentValues values){throw new UnsupportedOperationException();}
    /** 测试提供者只读。 */ @Override public int delete(Uri uri,String selection,String[] args){throw new UnsupportedOperationException();}
    /** 测试提供者只读。 */ @Override public int update(Uri uri,ContentValues values,String selection,String[] args){throw new UnsupportedOperationException();}
}
