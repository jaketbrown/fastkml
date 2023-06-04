#!/usr/bin/env python3
import atheris
import sys
import datetime

with atheris.instrument_imports(include=['fastkml']):
    import fastkml as kml
    from fastkml.enums import DateTimeResolution
    from fastkml.times import KmlDateTime
    from fastkml import atom
    from fastkml import base
    from fastkml import config
    from fastkml import data
    from fastkml import kml
    from fastkml import styles
    from fastkml.geometry import Geometry
    from fastkml.geometry import GeometryCollection
    from fastkml.geometry import LinearRing
    from fastkml.geometry import LineString
    from fastkml.geometry import MultiLineString
    from fastkml.geometry import MultiPoint
    from fastkml.geometry import MultiPolygon
    from fastkml.geometry import Point
    from fastkml.geometry import Polygon
    from fastkml.gx import GxGeometry

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    if len(data) == 0:
        return 0
    year = fdp.ConsumeIntInRange(1900, 2023)
    day = fdp.ConsumeIntInRange(1, 12)
    month = fdp.ConsumeIntInRange(1, 12)
    choice = fdp.ConsumeIntInRange(0, 10)
    consumed_bytes = fdp.ConsumeBytes(fdp.ConsumeIntInRange(20, 2000))
    try:
        if choice == 1:
            dt = datetime.datetime(year=year, day=day, month=month)
            KmlDateTime(dt, DateTimeResolution.year)
        elif choice == 2:
            kml._Feature(name="A Feature")
        elif choice == 3:
            KmlDateTime.parse(str(year) + "-03")
            KmlDateTime.parse(str(year))
        elif choice == 4:
            now = KmlDateTime(datetime.datetime.now())
            y2k = KmlDateTime(datetime.datetime(year, day, month))
            kml.TimeSpan(end=now, begin=y2k)
        else:
            # Create the root KML object
            k = kml.KML()
            ns = "{http://www.opengis.net/kml/2.2}"  # noqa: FS003

            # Create a KML Document and add it to the KML root object
            d = kml.Document(ns, "docid", "doc name", consumed_bytes.decode('utf-8'))
            k.append(d)

            # Create a KML Folder and add it to the Document
            f = kml.Folder(ns, "fid", "f name", consumed_bytes.decode('utf-8'))
            d.append(f)

            # Create a KML Folder and nest it in the first Folder
            nf = kml.Folder(ns, "nested-fid", "nested f name", consumed_bytes.decode('utf-8'))
            f.append(nf)
    except UnicodeDecodeError:
        return
    except Exception:
        raise

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
