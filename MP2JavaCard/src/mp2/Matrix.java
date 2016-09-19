package mp2;

/**
 * Matrix structure class
 * {a,b
 *  c,d}
 * 
 * @author Rui
 *
 */
public class Matrix {
	public byte[] a;
	public byte[] b;
	public byte[] c;
	public byte[] d;
	
	public Matrix(short elementByteLength)
	{
		this.a = new byte[elementByteLength];
		this.b = new byte[elementByteLength];	
		this.c = new byte[elementByteLength];	
		this.d = new byte[elementByteLength];
		
		elementByteLength--;
		this.a[elementByteLength] = 1;
		this.d[elementByteLength] = 1;
	}
}