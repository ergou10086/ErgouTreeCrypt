package hbnu.project.ergoutreecrypt.android;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/** 验收变体或测试 APK 的可写 SAF 提供者；故障只影响本测试私有目录。 */
public final class FastTestDocumentsProvider extends ContentProvider {
    private File root;
    private boolean failWrite;
    private boolean failRename;

    /** @return 测试目录是否就绪 */
    @Override public boolean onCreate() {
        root = new File(getContext().getFilesDir(), "fast-saf-provider");
        return root.isDirectory() || root.mkdirs();
    }

    /**
     * @param id 相对文档标识
     * @return 测试私有路径
     * @throws FileNotFoundException 非法标识
     */
    private File file(String id) throws FileNotFoundException {
        try {
            File result = id.equals("root") ? root : new File(root, id.substring(5));
            if (!result.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)
                    && !result.equals(root)) throw new IOException("越界");
            return result;
        } catch (Exception error) { throw new FileNotFoundException(error.toString()); }
    }

    /**
     * @param value 测试文件
     * @return 稳定的相对标识
     */
    private String id(File value) { return "root/" + root.toPath().relativize(value.toPath()); }

    /**
     * @param projection 需要的列
     * @return 测试根目录
     */
    public Cursor queryRoots(String[] projection) {
        var result = new MatrixCursor(new String[]{Root.COLUMN_ROOT_ID, Root.COLUMN_DOCUMENT_ID,
                Root.COLUMN_TITLE, Root.COLUMN_FLAGS});
        result.addRow(new Object[]{"root", "root", "FAST测试", Root.FLAG_SUPPORTS_CREATE});
        return result;
    }

    /**
     * @param id 文档标识
     * @param projection 需要的列
     * @return 文档属性
     * @throws FileNotFoundException 不存在
     */
    public Cursor queryDocument(String id, String[] projection) throws FileNotFoundException {
        var result = cursor();
        add(result, file(id));
        return result;
    }

    /**
     * @param parent 父文档
     * @param projection 需要的列
     * @param sortOrder 排序
     * @return 子文档
     * @throws FileNotFoundException 不存在
     */
    public Cursor queryChildDocuments(String parent, String[] projection, String sortOrder) throws FileNotFoundException {
        var result = cursor();
        File[] children = file(parent).listFiles();
        if (children != null) for (File child : children) add(result, child);
        return result;
    }

    /** @return 文档属性游标 */
    private MatrixCursor cursor() {
        return new MatrixCursor(new String[]{Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME,
                Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE, Document.COLUMN_FLAGS});
    }

    /**
     * @param cursor 属性游标
     * @param value 本次文档
     */
    private void add(MatrixCursor cursor, File value) {
        cursor.addRow(new Object[]{value.equals(root) ? "root" : id(value), value.getName(),
                value.isDirectory() ? Document.MIME_TYPE_DIR : "application/octet-stream", value.length(),
                Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_DELETE | Document.FLAG_SUPPORTS_RENAME
                        | (value.isDirectory() ? Document.FLAG_DIR_SUPPORTS_CREATE : 0)});
    }

    /**
     * @param parent 父文档
     * @param mime 类型
     * @param name 名称
     * @return 新标识
     * @throws FileNotFoundException 创建失败
     */
    public String createDocument(String parent, String mime, String name) throws FileNotFoundException {
        File child = new File(file(parent), name);
        try {
            if (child.exists() || !(Document.MIME_TYPE_DIR.equals(mime) ? child.mkdir() : child.createNewFile()))
                throw new IOException("已存在或创建失败");
            return id(child);
        } catch (IOException error) { throw new FileNotFoundException(error.toString()); }
    }

    /**
     * @param document 文档
     * @param mode 打开方式
     * @param signal 取消信号
     * @return 描述符
     * @throws FileNotFoundException 注入磁盘满或打开失败
     */
    public ParcelFileDescriptor openDocument(String document, String mode, CancellationSignal signal) throws FileNotFoundException {
        if ("root/keyfile-denied".equals(document)) throw new SecurityException("Injected keyfile permission denial");
        if (failWrite && mode.contains("w")) throw new FileNotFoundException("ENOSPC（注入故障）");
        return ParcelFileDescriptor.open(file(document), ParcelFileDescriptor.parseMode(mode));
    }

    /**
     * @param document 文档
     * @param name 新名称
     * @return 新标识
     * @throws FileNotFoundException 提交失败
     */
    public String renameDocument(String document, String name) throws FileNotFoundException {
        File source = file(document), target = new File(source.getParentFile(), name);
        if (failRename || target.exists() || !source.renameTo(target)) throw new FileNotFoundException("提交失败");
        return id(target);
    }

    /**
     * @param document 本测试拥有的文档
     * @throws FileNotFoundException 删除失败
     */
    public void deleteDocument(String document) throws FileNotFoundException {
        delete(file(document));
    }

    /**
     * @param value 本测试目录内的文件
     * @throws FileNotFoundException 删除失败
     */
    private void delete(File value) throws FileNotFoundException {
        File[] children = value.listFiles();
        if (children != null) for (File child : children) delete(child);
        if (!value.delete()) throw new FileNotFoundException(value.toString());
    }

    /**
     * @param method 测试指令
     * @param arg 开关
     * @param extras 附加参数
     * @return 指令结果
     */
    @Override public Bundle call(String method, String arg, Bundle extras) {
        if (method.startsWith("android:")) {
            try {
                Uri uri = extras.getParcelable("uri");
                String document = DocumentsContract.getDocumentId(uri);
                Bundle result = new Bundle();
                if (method.equals("android:createDocument")) {
                    String created = createDocument(document, extras.getString("mime_type"), extras.getString("_display_name"));
                    result.putParcelable("uri", DocumentsContract.buildDocumentUriUsingTree(uri, created));
                } else if (method.equals("android:renameDocument")) {
                    String renamed = renameDocument(document, extras.getString("_display_name"));
                    result.putParcelable("uri", DocumentsContract.buildDocumentUriUsingTree(uri, renamed));
                } else if (method.equals("android:deleteDocument")) deleteDocument(document);
                else throw new UnsupportedOperationException(method);
                return result;
            } catch (IOException error) { throw new IllegalStateException(error); }
        }
        if (method.equals("fast.reset")) {
            try { delete(root); root.mkdirs(); } catch (Exception error) { throw new IllegalStateException(error); }
            failWrite = false; failRename = false;
        } else if (method.equals("fast.failWrite")) failWrite = Boolean.parseBoolean(arg);
        else if (method.equals("fast.failRename")) failRename = Boolean.parseBoolean(arg);
        else return super.call(method, arg, extras);
        return new Bundle();
    }

    /**
     * @param uri 文档 URI
     * @param projection 属性列
     * @param selection 筛选
     * @param args 筛选参数
     * @param order 排序
     * @return 文档属性
     */
    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        try {
            String document = DocumentsContract.getDocumentId(uri);
            return "children".equals(uri.getLastPathSegment())
                    ? queryChildDocuments(document, projection, order) : queryDocument(document, projection);
        } catch (IOException error) { throw new IllegalStateException(error); }
    }

    /**
     * @param uri 文档 URI
     * @param mode 打开方式
     * @return 文件描述符
     * @throws FileNotFoundException 打开失败
     */
    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if ("relay".equals(uri.getPathSegments().get(0))) {
            return ParcelFileDescriptor.open(relay(uri), ParcelFileDescriptor.parseMode(mode));
        }
        return openDocument(DocumentsContract.getDocumentId(uri), mode, null);
    }

    /**
     * @param uri 独占中转文件 URI
     * @return 测试缓存文件
     * @throws FileNotFoundException 非法名称
     */
    private File relay(Uri uri) throws FileNotFoundException {
        String name = uri.getLastPathSegment();
        if (uri.getPathSegments().size() != 2 || name == null
                || !name.matches("fast-(interop|benchmark)-[a-f0-9]{32}\\.zip"))
            throw new FileNotFoundException("非法中转名称");
        return new File(getContext().getCacheDir(), name);
    }

    /**
     * @param uri 文档 URI
     * @return 文件类型
     */
    @Override public String getType(Uri uri) { return "application/octet-stream"; }
    /**
     * @param uri 文档 URI
     * @param values 属性
     * @return 不支持直接插入
     */
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    /**
     * @param uri 独占中转 URI
     * @param selection 筛选
     * @param args 筛选参数
     * @return 删除的中转文件数
     */
    @Override public int delete(Uri uri, String selection, String[] args) {
        try { return relay(uri).delete() ? 1 : 0; }
        catch (FileNotFoundException error) { throw new IllegalArgumentException(error); }
    }
    /**
     * @param uri 文档 URI
     * @param values 属性
     * @param selection 筛选
     * @param args 筛选参数
     * @return 不支持直接修改
     */
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
